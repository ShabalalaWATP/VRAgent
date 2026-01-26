import React, { useState, useCallback, useRef, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  TextField,
  Paper,
  Chip,
  Alert,
  CircularProgress,
  alpha,
  useTheme,
  Tooltip,
  IconButton,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  LinearProgress,
  Checkbox,
  FormControlLabel,
  Divider,
  Badge,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Collapse,
  Stepper,
  Step,
  StepLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Switch,
} from "@mui/material";
import { Link } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import RefreshIcon from "@mui/icons-material/Refresh";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SecurityIcon from "@mui/icons-material/Security";
import BugReportIcon from "@mui/icons-material/BugReport";
import SpeedIcon from "@mui/icons-material/Speed";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import InfoIcon from "@mui/icons-material/Info";
import PsychologyIcon from "@mui/icons-material/Psychology";
import TimelineIcon from "@mui/icons-material/Timeline";
import RadarIcon from "@mui/icons-material/Radar";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import TuneIcon from "@mui/icons-material/Tune";
import AssessmentIcon from "@mui/icons-material/Assessment";
import MemoryIcon from "@mui/icons-material/Memory";
import FingerprintIcon from "@mui/icons-material/Fingerprint";
import ShieldIcon from "@mui/icons-material/Shield";
import CodeIcon from "@mui/icons-material/Code";
import LinkIcon from "@mui/icons-material/Link";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import TimerIcon from "@mui/icons-material/Timer";
import ExploreIcon from "@mui/icons-material/Explore";
import ScheduleIcon from "@mui/icons-material/Schedule";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import SaveIcon from "@mui/icons-material/Save";
import DownloadIcon from "@mui/icons-material/Download";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import ComputerIcon from "@mui/icons-material/Computer";
import LanIcon from "@mui/icons-material/Lan";
import RouterIcon from "@mui/icons-material/Router";
import TerminalIcon from "@mui/icons-material/Terminal";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import SchoolIcon from "@mui/icons-material/School";
import CloseIcon from "@mui/icons-material/Close";
import DeleteIcon from "@mui/icons-material/Delete";
import HistoryIcon from "@mui/icons-material/History";
import VisibilityIcon from "@mui/icons-material/Visibility";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import VerifiedUserIcon from "@mui/icons-material/VerifiedUser";
import WarningIcon from "@mui/icons-material/Warning";
import AssignmentTurnedInIcon from "@mui/icons-material/AssignmentTurnedIn";

const API_BASE = "/api";

// Helper component to render report data in a readable format
const ReportSection: React.FC<{ 
  title: string; 
  data: any; 
  color?: string;
  icon?: React.ReactNode;
}> = ({ title, data, color = "#00ffff", icon }) => {
  if (!data) return null;
  
  // Function to render any value nicely
  const renderValue = (value: any, depth: number = 0): React.ReactNode => {
    if (value === null || value === undefined) return null;
    
    if (typeof value === 'string') {
      return <Typography variant="body2" sx={{ whiteSpace: "pre-wrap", ml: depth * 2 }}>{value}</Typography>;
    }
    
    if (typeof value === 'number' || typeof value === 'boolean') {
      return <Typography variant="body2" sx={{ ml: depth * 2 }}>{String(value)}</Typography>;
    }
    
    if (Array.isArray(value)) {
      return (
        <Box sx={{ ml: depth * 2 }}>
          {value.map((item, i) => (
            <Box key={i} sx={{ mb: 1, pl: 1, borderLeft: "2px solid rgba(255,255,255,0.1)" }}>
              {typeof item === 'string' ? (
                <Typography variant="body2">• {item}</Typography>
              ) : typeof item === 'object' && item !== null ? (
                <Box>
                  {Object.entries(item).map(([k, v]) => (
                    <Box key={k} sx={{ mb: 0.5 }}>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)", fontWeight: "bold" }}>
                        {k.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:
                      </Typography>
                      {renderValue(v, 0)}
                    </Box>
                  ))}
                </Box>
              ) : (
                <Typography variant="body2">• {String(item)}</Typography>
              )}
            </Box>
          ))}
        </Box>
      );
    }
    
    if (typeof value === 'object') {
      return (
        <Box sx={{ ml: depth * 2 }}>
          {Object.entries(value).map(([key, val]) => (
            <Box key={key} sx={{ mb: 1 }}>
              <Typography 
                variant="caption" 
                sx={{ 
                  color: "rgba(255,255,255,0.7)", 
                  fontWeight: "bold",
                  textTransform: "capitalize"
                }}
              >
                {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}:
              </Typography>
              {renderValue(val, depth + 1)}
            </Box>
          ))}
        </Box>
      );
    }
    
    return <Typography variant="body2" sx={{ ml: depth * 2 }}>{String(value)}</Typography>;
  };
  
  return (
    <Box sx={{ mb: 3 }}>
      <Typography 
        variant="subtitle1" 
        sx={{ 
          color, 
          mb: 1.5, 
          fontWeight: "bold",
          display: "flex",
          alignItems: "center",
          gap: 1,
          borderBottom: `1px solid ${color}33`,
          pb: 0.5
        }}
      >
        {icon}
        {title}
      </Typography>
      <Box sx={{ pl: 1 }}>
        {renderValue(data)}
      </Box>
    </Box>
  );
};

// Saved report interface
interface SavedReport {
  id: number;
  session_id?: string;
  title: string;
  target_url: string;
  scan_profile?: string;
  completed_at: string | null;
  duration_seconds?: number;
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
}

interface TechFingerprint {
  server?: string;
  framework?: string;
  language?: string;
  cms?: string;
  waf: string;
  waf_confidence: number;
  technologies: string[];
}

interface DiscoveredEndpoint {
  url: string;
  method: string;
  parameters: string[];
  source: string;
  confidence: number;
}

interface AttackChainStep {
  order: number;
  technique: string;
  payload: string;
  expected_outcome: string;
  actual_outcome?: string;
  success: boolean;
}

interface AttackChain {
  id: string;
  name: string;
  description: string;
  steps: AttackChainStep[];
  current_step: number;
  status: string;
  final_impact: string;
}

interface BlindDetectionResult {
  technique: string;
  detected: boolean;
  detection_method: string;
  baseline_time: number;
  payload_time: number;
  time_difference: number;
  confidence: number;
}

interface FuzzingTechnique {
  id: string;
  name: string;
  category: string;
}

interface FuzzingPreset {
  id: string;
  name: string;
  description: string;
  max_iterations: number;
  techniques: string[];
  depth: string;
}

interface FuzzingFinding {
  id: string;
  technique: string;
  severity: string;
  title: string;
  description: string;
  payload: string;
  evidence: string[];
  endpoint: string;
  parameter?: string;
  cvss_score?: number;
  cvss_vector?: string;
  proof_of_concept?: string;
  cwe_id?: string;
  recommendation?: string;
}

// ETA estimation interface
interface ScanETA {
  scan_id: string;
  estimated_duration_seconds: number;
  start_time: string;
  estimated_completion_time: string;
  current_phase: string;
  phase_progress: number;
  overall_progress: number;
  time_elapsed_seconds: number;
  time_remaining_seconds: number;
  iterations_completed: number;
  iterations_total: number;
  findings_count: number;
  confidence: string; // HIGH, MEDIUM, LOW
  phase_times: Record<string, number>;
  is_complete: boolean;
}

// Enhanced progress tracking interface
interface PhaseDetails {
  name: string;
  label: string;
  status: string;
  progress: number;
}

interface DetailedProgress {
  scan_id: string;
  status: string;
  overall_progress: number;
  current_phase: string;
  current_phase_details?: {
    name: string;
    status: string;
    elapsed_seconds: number;
    current_step: number;
    total_steps: number;
    progress_percent: number;
    message: string;
  };
  iteration: number;
  max_iterations: number;
  time_elapsed_seconds: number;
  time_remaining_seconds: number | null;
  estimated_completion: string | null;
  metrics: {
    requests_made: number;
    findings_count: number;
    endpoints_discovered: number;
    techniques_tested: number;
  };
  phase_timeline: PhaseDetails[];
  recent_activity: { timestamp: string; message: string }[];
  errors_count: number;
  warnings_count: number;
}

interface FuzzingUpdate {
  type: string;
  session_id?: string;
  phase?: string;
  technique?: string;
  message?: string;
  iteration?: number;
  max_iterations?: number;
  findings?: FuzzingFinding[];
  finding?: FuzzingFinding;
  analysis?: string;
  decision?: string;
  reasoning?: string;
  progress?: number;
  error?: string;
  fingerprints?: TechFingerprint[];
  cvss_score?: number;
  eta?: ScanETA; // Add ETA to update interface
  // Enhanced progress tracking
  overall_progress?: number;
  current_phase_details?: DetailedProgress["current_phase_details"];
  metrics?: DetailedProgress["metrics"];
  phase_timeline?: PhaseDetails[];
  recent_activity?: { timestamp: string; message: string }[];
  // New fields for enhanced capabilities
  endpoints_found?: DiscoveredEndpoint[];
  parameters_found?: string[];
  chain?: AttackChain;
  blind_detection_results?: BlindDetectionResult[];
  total_targets?: number;
  summary?: {
    total_requests: number;
    findings_count: number;
    duration_seconds: number;
    techniques_used: string[];
  };
}

const AgenticFuzzerPage: React.FC = () => {
  const theme = useTheme();
  const { getAccessToken } = useAuth();
  
  // Debug
  console.log("[AgenticFuzzerPage] Component mounting...");
  
  // State
  const [targetUrl, setTargetUrl] = useState("");
  const [method, setMethod] = useState("AUTO");
  const [headers, setHeaders] = useState("");
  const [body, setBody] = useState("");
  const [selectedTechniques, setSelectedTechniques] = useState<string[]>([]);
  const [maxIterations, setMaxIterations] = useState(50);
  const [depth, setDepth] = useState("normal");
  const [selectedPreset, setSelectedPreset] = useState("");
  
  // Stealth Mode state
  const [stealthMode, setStealthMode] = useState(false);
  const [stealthDelayMin, setStealthDelayMin] = useState(2.0);
  const [stealthDelayMax, setStealthDelayMax] = useState(5.0);
  const [stealthRequestsBeforePause, setStealthRequestsBeforePause] = useState(10);
  const [stealthPauseDuration, setStealthPauseDuration] = useState(30.0);
  const [stealthIpRenewalEnabled, setStealthIpRenewalEnabled] = useState(false);
  const [stealthIpRenewalInterval, setStealthIpRenewalInterval] = useState(50);
  const [ipRenewalPending, setIpRenewalPending] = useState(false);
  
  const [techniques, setTechniques] = useState<FuzzingTechnique[]>([]);
  const [presets, setPresets] = useState<FuzzingPreset[]>([]);
  
  const [isRunning, setIsRunning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [currentPhase, setCurrentPhase] = useState("");
  const [currentTechnique, setCurrentTechnique] = useState("");
  const [progress, setProgress] = useState(0);
  const [iteration, setIteration] = useState(0);
  const [maxIter, setMaxIter] = useState(0);
  
  const [updates, setUpdates] = useState<FuzzingUpdate[]>([]);
  const [findings, setFindings] = useState<FuzzingFinding[]>([]);
  const [llmAnalysis, setLlmAnalysis] = useState<string[]>([]);
  const [fingerprint, setFingerprint] = useState<TechFingerprint | null>(null);
  const [showPoc, setShowPoc] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<FuzzingUpdate["summary"] | null>(null);
  
  // New state for enhanced capabilities
  const [discoveredEndpoints, setDiscoveredEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [attackChains, setAttackChains] = useState<AttackChain[]>([]);
  const [blindResults, setBlindResults] = useState<BlindDetectionResult[]>([]);
  const [totalTargets, setTotalTargets] = useState(1);
  const [showChainDetails, setShowChainDetails] = useState<string | null>(null);
  
  // ETA state
  const [eta, setEta] = useState<ScanETA | null>(null);
  
  // Enhanced progress tracking state
  const [detailedProgress, setDetailedProgress] = useState<DetailedProgress | null>(null);
  
  // Report state
  const [finalReport, setFinalReport] = useState<any>(null);
  const [savedReportId, setSavedReportId] = useState<number | null>(null);
  const [isSavingReport, setIsSavingReport] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  
  // Saved reports state
  const [savedReports, setSavedReports] = useState<SavedReport[]>([]);
  const [isLoadingReports, setIsLoadingReports] = useState(false);
  const [showReportsPanel, setShowReportsPanel] = useState(false);
  const [selectedSavedReport, setSelectedSavedReport] = useState<any>(null);
  const [viewingReportId, setViewingReportId] = useState<number | null>(null);
  
  // Help dialog state
  const [showSetupGuide, setShowSetupGuide] = useState(false);
  
  const abortControllerRef = useRef<AbortController | null>(null);
  const updatesEndRef = useRef<HTMLDivElement>(null);
  
  // Load techniques and presets on mount
  useEffect(() => {
    const loadData = async () => {
      console.log("[AgenticFuzzerPage] Loading techniques and presets...");
      const token = getAccessToken();
      try {
        const [techRes, presetRes] = await Promise.all([
          fetch(`${API_BASE}/agentic-fuzzer/techniques`, {
            headers: { "Authorization": `Bearer ${token}` },
          }),
          fetch(`${API_BASE}/agentic-fuzzer/presets`, {
            headers: { "Authorization": `Bearer ${token}` },
          }),
        ]);
        
        console.log("[AgenticFuzzerPage] Tech response:", techRes.status);
        console.log("[AgenticFuzzerPage] Preset response:", presetRes.status);
        
        if (techRes.ok) {
          const data = await techRes.json();
          setTechniques(data.techniques || []);
        }
        
        if (presetRes.ok) {
          const data = await presetRes.json();
          setPresets(data.presets || []);
        }
      } catch (err) {
        console.error("[AgenticFuzzerPage] Failed to load fuzzer data:", err);
      }
    };
    
    loadData();
  }, []);
  
  // Scroll to bottom of updates
  useEffect(() => {
    updatesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [updates]);
  
  // Load saved reports
  const loadSavedReports = useCallback(async () => {
    setIsLoadingReports(true);
    try {
      const response = await fetch(`${API_BASE}/agentic-fuzzer/reports`, {
        headers: {
          "Authorization": `Bearer ${getAccessToken()}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        // API returns { total, skip, limit, reports: [...] }
        setSavedReports(data.reports || []);
      }
    } catch (err) {
      console.error("Failed to load saved reports:", err);
    } finally {
      setIsLoadingReports(false);
    }
  }, []);
  
  // View a specific saved report
  const viewSavedReport = useCallback(async (reportId: number) => {
    setViewingReportId(reportId);
    try {
      const response = await fetch(`${API_BASE}/agentic-fuzzer/reports/${reportId}`, {
        headers: {
          "Authorization": `Bearer ${getAccessToken()}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setSelectedSavedReport(data);
      }
    } catch (err) {
      console.error("Failed to load report:", err);
    } finally {
      setViewingReportId(null);
    }
  }, []);
  
  // Delete a saved report
  const deleteSavedReport = useCallback(async (reportId: number) => {
    if (!window.confirm("Are you sure you want to delete this report?")) {
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/agentic-fuzzer/reports/${reportId}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${getAccessToken()}`,
        },
      });
      if (response.ok) {
        setSavedReports(prev => prev.filter(r => r.id !== reportId));
        if (selectedSavedReport?.id === reportId) {
          setSelectedSavedReport(null);
        }
      }
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  }, [selectedSavedReport]);
  
  // Load reports when panel is opened
  useEffect(() => {
    if (showReportsPanel) {
      loadSavedReports();
    }
  }, [showReportsPanel, loadSavedReports]);
  
  // Update max iterations when depth changes
  useEffect(() => {
    const depthToIterations: Record<string, number> = {
      minimal: 25,
      quick: 50,
      normal: 150,
      thorough: 500,
      aggressive: 1500,
    };
    if (depthToIterations[depth]) {
      setMaxIterations(depthToIterations[depth]);
    }
  }, [depth]);
  
  // Apply preset
  const applyPreset = useCallback((presetId: string) => {
    const preset = presets.find(p => p.id === presetId);
    if (preset) {
      setSelectedPreset(presetId);
      setMaxIterations(preset.max_iterations);
      setDepth(preset.depth);
      setSelectedTechniques(preset.techniques.length > 0 ? preset.techniques : []);
    }
  }, [presets]);
  
  // Toggle technique selection
  const toggleTechnique = useCallback((techId: string) => {
    setSelectedTechniques(prev => 
      prev.includes(techId) 
        ? prev.filter(t => t !== techId)
        : [...prev, techId]
    );
    setSelectedPreset(""); // Clear preset when manually selecting
  }, []);
  
  // Start fuzzing
  const startFuzzing = useCallback(async () => {
    if (!targetUrl) {
      setError("Please enter a target URL");
      return;
    }
    
    // Normalize URL - add http:// if no protocol specified
    let normalizedUrl = targetUrl.trim();
    if (!normalizedUrl.startsWith('http://') && !normalizedUrl.startsWith('https://')) {
      normalizedUrl = `http://${normalizedUrl}`;
    }
    
    setIsRunning(true);
    setError(null);
    setUpdates([]);
    setFindings([]);
    setLlmAnalysis([]);
    setSummary(null);
    setProgress(0);
    setIteration(0);
    setEta(null); // Reset ETA on new scan
    setFinalReport(null); // Reset final report
    setSavedReportId(null); // Reset saved report ID
    setDetailedProgress(null); // Reset detailed progress
    
    abortControllerRef.current = new AbortController();
    
    try {
      // Parse headers
      const headerObj: Record<string, string> = {};
      if (headers.trim()) {
        headers.split("\n").forEach(line => {
          const [key, ...values] = line.split(":");
          if (key && values.length) {
            headerObj[key.trim()] = values.join(":").trim();
          }
        });
      }
      
      const payload = {
        targets: [{
          url: normalizedUrl,
          method,
          headers: headerObj,
          body: body || undefined,
        }],
        techniques: selectedTechniques.length > 0 ? selectedTechniques : undefined,
        max_iterations: maxIterations,
        depth,
        // Stealth Mode settings
        stealth_mode: stealthMode,
        stealth_delay_min: stealthDelayMin,
        stealth_delay_max: stealthDelayMax,
        stealth_requests_before_pause: stealthRequestsBeforePause,
        stealth_pause_duration: stealthPauseDuration,
        stealth_randomize_user_agent: true,
        stealth_randomize_headers: true,
        stealth_ip_renewal_enabled: stealthIpRenewalEnabled,
        stealth_ip_renewal_interval: stealthIpRenewalInterval,
      };
      
      const response = await fetch(`${API_BASE}/agentic-fuzzer/start`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${getAccessToken()}`,
        },
        body: JSON.stringify(payload),
        signal: abortControllerRef.current.signal,
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
      }
      
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      
      if (!reader) {
        throw new Error("No response body");
      }
      
      let buffer = "";
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const update: FuzzingUpdate = JSON.parse(line.slice(6));
              
              setUpdates(prev => [...prev, update]);
              
              if (update.session_id) {
                setSessionId(update.session_id);
              }
              
              if (update.phase) {
                setCurrentPhase(update.phase);
              }
              
              if (update.technique) {
                setCurrentTechnique(update.technique);
              }
              
              if (update.iteration !== undefined && update.max_iterations !== undefined) {
                setIteration(update.iteration);
                setMaxIter(update.max_iterations);
                setProgress((update.iteration / update.max_iterations) * 100);
              }
              
              if (update.finding) {
                setFindings(prev => [...prev, update.finding!]);
              }
              
              if (update.findings) {
                setFindings(update.findings);
              }
              
              if (update.analysis) {
                setLlmAnalysis(prev => [...prev, update.analysis!]);
              }
              
              if (update.fingerprints && update.fingerprints.length > 0) {
                setFingerprint(update.fingerprints[0]);
              }
              
              if (update.summary) {
                setSummary(update.summary);
              }
              
              // Handle new enhanced events
              if (update.endpoints_found && Array.isArray(update.endpoints_found)) {
                setDiscoveredEndpoints(prev => [...prev, ...update.endpoints_found!]);
              }
              
              // Handle chain updates (from chain_update events or any event with chain data)
              if (update.chain || update.type === "chain_update") {
                const chainData = update.chain || (update as any).chain;
                if (chainData) {
                  setAttackChains(prev => {
                    const existing = prev.findIndex(c => c.id === chainData.id);
                    if (existing >= 0) {
                      const updated = [...prev];
                      updated[existing] = chainData;
                      return updated;
                    }
                    return [...prev, chainData];
                  });
                }
              }
              
              if (update.blind_detection_results) {
                setBlindResults(prev => [...prev, ...update.blind_detection_results!]);
              }
              
              if (update.total_targets) {
                setTotalTargets(update.total_targets);
              }
              
              // Parse ETA updates
              if (update.eta) {
                setEta(update.eta);
              }
              
              // Handle enhanced progress tracking events
              if (update.type === "progress_update") {
                setDetailedProgress({
                  scan_id: update.session_id || "",
                  status: (update as any).status || "running",
                  overall_progress: update.overall_progress || 0,
                  current_phase: (update as any).current_phase || "",
                  current_phase_details: update.current_phase_details,
                  iteration: update.iteration || 0,
                  max_iterations: update.max_iterations || 0,
                  time_elapsed_seconds: (update as any).time_elapsed_seconds || 0,
                  time_remaining_seconds: (update as any).time_remaining_seconds,
                  estimated_completion: (update as any).estimated_completion,
                  metrics: update.metrics || { requests_made: 0, findings_count: 0, endpoints_discovered: 0, techniques_tested: 0 },
                  phase_timeline: update.phase_timeline || [],
                  recent_activity: update.recent_activity || [],
                  errors_count: (update as any).errors_count || 0,
                  warnings_count: (update as any).warnings_count || 0,
                });
                // Also update the simple progress indicator
                if (update.overall_progress !== undefined) {
                  setProgress(update.overall_progress);
                }
              }
              
              if (update.error) {
                setError(update.error);
              }
              
              // Handle IP renewal needed events (for stealth mode) - with error protection
              try {
                if (update.type === "ip_renewal_needed" || (update as any).ip_renewal_needed) {
                  setIpRenewalPending(true);
                }
              } catch (ipErr) {
                console.warn("[AgenticFuzzerPage] IP renewal event handling failed:", ipErr);
              }
              
              // Capture final report for saving/exporting
              if (update.type === "final_report") {
                console.log("[AgenticFuzzerPage] Final report received:", JSON.stringify(update, null, 2));
                setFinalReport(update);
                
                // AUTO-SAVE: Automatically save report to database when scan completes
                try {
                  const autoSaveResponse = await fetch(`${API_BASE}/agentic-fuzzer/reports/save-from-final-report`, {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      "Authorization": `Bearer ${getAccessToken()}`,
                    },
                    body: JSON.stringify({
                      final_report: update,
                      title: `Security Scan: ${targetUrl}`,
                      project_id: null, // Can be set if inside a project context
                    }),
                  });
                  
                  if (autoSaveResponse.ok) {
                    const saveData = await autoSaveResponse.json();
                    setSavedReportId(saveData.report_id);
                    console.log("[AgenticFuzzerPage] Report auto-saved with ID:", saveData.report_id);
                  } else {
                    console.warn("[AgenticFuzzerPage] Auto-save failed:", autoSaveResponse.status);
                  }
                } catch (autoSaveErr) {
                  console.warn("[AgenticFuzzerPage] Auto-save error:", autoSaveErr);
                  // Don't show error to user - they can still manually save
                }
              }
              
              if (update.type === "complete" || update.type === "error" || update.type === "final_report") {
                setIsRunning(false);
                // Mark ETA as complete
                if (eta) {
                  setEta(prev => prev ? { ...prev, is_complete: true } : null);
                }
              }
            } catch (e) {
              console.error("Failed to parse SSE update:", e);
            }
          }
        }
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        setError(err.message || "Fuzzing failed");
      }
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
    }
  }, [targetUrl, method, headers, body, selectedTechniques, maxIterations, depth]);
  
  // Stop fuzzing
  const stopFuzzing = useCallback(async () => {
    abortControllerRef.current?.abort();
    
    if (sessionId) {
      try {
        await fetch(`${API_BASE}/agentic-fuzzer/sessions/${sessionId}/stop`, {
          method: "POST",
          headers: {
            "Authorization": `Bearer ${getAccessToken()}`,
          },
        });
      } catch (err) {
        console.error("Failed to stop session:", err);
      }
    }
    
    setIsRunning(false);
  }, [sessionId]);
  
  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical": return theme.palette.error.main;
      case "high": return "#ff5722";
      case "medium": return theme.palette.warning.main;
      case "low": return theme.palette.info.main;
      default: return theme.palette.text.secondary;
    }
  };
  
  // Format duration as human-readable string
  const formatDuration = (seconds: number | null | undefined): string => {
    if (seconds === null || seconds === undefined || isNaN(seconds)) return "Calculating...";
    if (seconds < 0) return "Calculating...";
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) {
      const mins = Math.floor(seconds / 60);
      const secs = Math.round(seconds % 60);
      return `${mins}m ${secs}s`;
    }
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  };
  
  // Format time as HH:MM:SS for completion time
  const formatCompletionTime = (isoString: string): string => {
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return "N/A";
    }
  };
  
  // Get confidence color
  const getConfidenceColor = (confidence: string) => {
    switch (confidence?.toUpperCase()) {
      case "HIGH": return theme.palette.success.main;
      case "MEDIUM": return theme.palette.warning.main;
      case "LOW": return theme.palette.error.light;
      default: return theme.palette.text.secondary;
    }
  };
  
  // Get phase icon
  const getPhaseIcon = (phase: string) => {
    switch (phase) {
      case "reconnaissance": return <RadarIcon />;
      case "fingerprinting": return <FingerprintIcon />;
      case "discovery": return <ExploreIcon />;
      case "technique_selection": return <TuneIcon />;
      case "payload_execution": return <MemoryIcon />;
      case "result_analysis": return <PsychologyIcon />;
      case "blind_detection": return <TimerIcon />;
      case "chain_exploitation": return <AccountTreeIcon />;
      case "exploitation": return <BugReportIcon />;
      case "reporting": return <AssessmentIcon />;
      case "completed": return <CheckCircleIcon />;
      default: return <TimelineIcon />;
    }
  };
  
  // Group techniques by category
  const techniquesByCategory = techniques.reduce((acc, tech) => {
    if (!acc[tech.category]) {
      acc[tech.category] = [];
    }
    acc[tech.category].push(tech);
    return acc;
  }, {} as Record<string, FuzzingTechnique[]>);

  // Save report to database
  const saveReport = useCallback(async () => {
    if (!finalReport || savedReportId) return;
    
    setIsSavingReport(true);
    try {
      const response = await fetch(`${API_BASE}/agentic-fuzzer/reports/save-from-final-report`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${getAccessToken()}`,
        },
        body: JSON.stringify({
          final_report: finalReport,
          title: `Security Scan: ${targetUrl}`,
        }),
      });
      
      if (!response.ok) {
        throw new Error(`Failed to save report: ${response.status}`);
      }
      
      const data = await response.json();
      setSavedReportId(data.report_id);
      console.log("[AgenticFuzzerPage] Report saved with ID:", data.report_id);
    } catch (err: any) {
      console.error("Failed to save report:", err);
      setError(`Failed to save report: ${err.message}`);
    } finally {
      setIsSavingReport(false);
    }
  }, [finalReport, savedReportId, targetUrl]);
  
  // Export report
  const exportReport = useCallback(async (format: "markdown" | "pdf" | "docx") => {
    let reportId = savedReportId;
    
    // If not saved yet, save first and get the ID directly from the response
    if (!reportId) {
      if (!finalReport) {
        setError("No report available to export");
        return;
      }
      
      setIsExporting(true);
      try {
        const response = await fetch(`${API_BASE}/agentic-fuzzer/reports/save-from-final-report`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${getAccessToken()}`,
          },
          body: JSON.stringify({
            final_report: finalReport,
            title: `Security Scan: ${targetUrl}`,
          }),
        });
        
        if (!response.ok) {
          throw new Error(`Failed to save report: ${response.status}`);
        }
        
        const data = await response.json();
        reportId = data.report_id;
        setSavedReportId(reportId);
        console.log("[AgenticFuzzerPage] Report saved for export with ID:", reportId);
      } catch (err: any) {
        console.error("Failed to save report for export:", err);
        setError(`Failed to save report: ${err.message}`);
        setIsExporting(false);
        return;
      }
    } else {
      setIsExporting(true);
    }
    
    if (!reportId) {
      setError("Please save the report first before exporting");
      setIsExporting(false);
      return;
    }
    
    try {
      const response = await fetch(`${API_BASE}/agentic-fuzzer/reports/${reportId}/export?format=${format}`, {
        headers: {
          "Authorization": `Bearer ${getAccessToken()}`,
        },
      });
      
      if (!response.ok) {
        throw new Error(`Export failed: ${response.status}`);
      }
      
      // Get filename from Content-Disposition header
      const contentDisposition = response.headers.get("Content-Disposition");
      let filename = `fuzzer_report_${sessionId}.${format === "markdown" ? "md" : format}`;
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="(.+)"/);
        if (match) filename = match[1];
      }
      
      // Download the file
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      console.log(`[AgenticFuzzerPage] Report exported as ${format}`);
    } catch (err: any) {
      console.error("Failed to export report:", err);
      setError(`Failed to export report: ${err.message}`);
    } finally {
      setIsExporting(false);
    }
  }, [savedReportId, finalReport, targetUrl, sessionId]);

  // Debug: Check if we reach the return
  console.log("[AgenticFuzzerPage] About to render, theme:", theme ? "loaded" : "null");
  
  // Temporary simple render test
  if (!theme) {
    return <div style={{ padding: 20, color: "white" }}>Loading theme...</div>;
  }
  
  return (
    <Box sx={{ 
      p: 3,
      minHeight: "100vh",
      background: "linear-gradient(135deg, #0a0a0f 0%, #1a0a2e 50%, #0f1a2e 100%)",
    }}>
      {/* Back to Security Fuzzer Link */}
      <Button
        component={Link}
        to="/dynamic/fuzzer"
        startIcon={<ArrowBackIcon />}
        sx={{
          mb: 3,
          color: "#00ffff",
          borderColor: "#00ffff",
          border: "1px solid",
          fontFamily: "'Orbitron', monospace",
          letterSpacing: "1px",
          px: 3,
          py: 1,
          "&:hover": {
            background: "rgba(0, 255, 255, 0.1)",
            borderColor: "#ff00ff",
            boxShadow: "0 0 20px rgba(0, 255, 255, 0.5)",
          },
        }}
      >
        Back to Security Fuzzer
      </Button>

      {/* Cyberpunk Header Banner */}
      <Box
        sx={{
          position: "relative",
          p: 4,
          mb: 4,
          background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.95) 50%, rgba(15, 26, 46, 0.95) 100%)",
          border: "2px solid transparent",
          borderImage: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff) 1",
          clipPath: "polygon(0 0, calc(100% - 20px) 0, 100% 20px, 100% 100%, 20px 100%, 0 calc(100% - 20px))",
          overflow: "hidden",
          "&::before": {
            content: '""',
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: "2px",
            background: "linear-gradient(90deg, transparent, #00ffff, #ff00ff, transparent)",
            animation: "scanLine 3s linear infinite",
          },
          "@keyframes scanLine": {
            "0%": { transform: "translateX(-100%)" },
            "100%": { transform: "translateX(100%)" },
          },
          "@keyframes glitchText": {
            "0%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
            "25%": { textShadow: "-2px 0 #ff00ff, 2px 0 #00ffff" },
            "50%": { textShadow: "2px 2px #ff00ff, -2px -2px #00ffff" },
            "75%": { textShadow: "-2px 2px #ff00ff, 2px -2px #00ffff" },
            "100%": { textShadow: "2px 0 #ff00ff, -2px 0 #00ffff" },
          },
          "@keyframes iconPulse": {
            "0%, 100%": { 
              filter: "drop-shadow(0 0 8px #ff00ff) drop-shadow(0 0 16px #00ffff)",
              transform: "scale(1)",
            },
            "50%": { 
              filter: "drop-shadow(0 0 16px #ff00ff) drop-shadow(0 0 32px #00ffff)",
              transform: "scale(1.05)",
            },
          },
        }}
      >
        {/* Corner Decorations */}
        <Box sx={{ position: "absolute", top: 0, left: 0, width: 40, height: 40, borderTop: "3px solid #00ffff", borderLeft: "3px solid #00ffff" }} />
        <Box sx={{ position: "absolute", top: 0, right: 0, width: 40, height: 40, borderTop: "3px solid #ff00ff", borderRight: "3px solid #ff00ff" }} />
        <Box sx={{ position: "absolute", bottom: 0, left: 0, width: 40, height: 40, borderBottom: "3px solid #ff00ff", borderLeft: "3px solid #ff00ff" }} />
        <Box sx={{ position: "absolute", bottom: 0, right: 0, width: 40, height: 40, borderBottom: "3px solid #00ffff", borderRight: "3px solid #00ffff" }} />

        <Box sx={{ display: "flex", alignItems: "center", gap: 3, position: "relative", zIndex: 1 }}>
          {/* Hexagonal Icon Container */}
          <Box
            sx={{
              width: 70,
              height: 70,
              background: "linear-gradient(135deg, #ff00ff 0%, #00ffff 100%)",
              clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              animation: "iconPulse 2s ease-in-out infinite",
              boxShadow: "0 0 30px rgba(255, 0, 255, 0.5), 0 0 60px rgba(0, 255, 255, 0.3)",
            }}
          >
            <SmartToyIcon sx={{ fontSize: 40, color: "#0a0a0f" }} />
          </Box>
          
          <Box>
            <Typography 
              variant="h3" 
              sx={{
                fontWeight: "bold",
                fontFamily: "'Orbitron', monospace",
                background: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff)",
                backgroundClip: "text",
                WebkitBackgroundClip: "text",
                WebkitTextFillColor: "transparent",
                textTransform: "uppercase",
                letterSpacing: "4px",
                animation: "glitchText 4s ease-in-out infinite",
                textShadow: "0 0 20px rgba(255, 0, 255, 0.5)",
              }}
            >
              Agentic Fuzzer
            </Typography>
            <Typography 
              variant="body1" 
              sx={{ 
                color: "#00ffff",
                mt: 1,
                fontFamily: "'Orbitron', monospace",
                letterSpacing: "2px",
                opacity: 0.9,
              }}
            >
              LLM-DRIVEN AUTONOMOUS FUZZING WITH INTELLIGENT DECISION-MAKING
            </Typography>
          </Box>
          
          <Box sx={{ flexGrow: 1 }} />
          
          <Button
            variant="outlined"
            startIcon={<HistoryIcon />}
            onClick={() => setShowReportsPanel(true)}
            sx={{ 
              mr: 2,
              color: "#ff9800",
              borderColor: "#ff9800",
              fontFamily: "'Orbitron', monospace",
              "&:hover": {
                borderColor: "#ff00ff",
                background: "rgba(255, 152, 0, 0.1)",
                boxShadow: "0 0 20px rgba(255, 152, 0, 0.5)",
              },
            }}
          >
            Saved Reports
          </Button>
          
          <Button
            variant="outlined"
            startIcon={<SchoolIcon />}
            onClick={() => setShowSetupGuide(true)}
            sx={{ 
              mr: 2,
              color: "#00ffff",
              borderColor: "#00ffff",
              fontFamily: "'Orbitron', monospace",
              "&:hover": {
                borderColor: "#ff00ff",
                background: "rgba(0, 255, 255, 0.1)",
                boxShadow: "0 0 20px rgba(0, 255, 255, 0.5)",
              },
            }}
          >
            Setup Guide
          </Button>
          
          <Chip 
            icon={<AutoAwesomeIcon sx={{ color: "#ff00ff !important" }} />}
            label="AI-POWERED"
            sx={{
              background: "rgba(255, 0, 255, 0.1)",
              border: "1px solid #ff00ff",
              color: "#ff00ff",
              fontFamily: "'Orbitron', monospace",
              fontWeight: "bold",
              boxShadow: "0 0 15px rgba(255, 0, 255, 0.3)",
              "& .MuiChip-icon": {
                color: "#ff00ff",
              },
            }}
          />
        </Box>
      </Box>

      {/* VM/Network Setup Guide Dialog */}
      <Dialog 
        open={showSetupGuide} 
        onClose={() => setShowSetupGuide(false)}
        maxWidth="md"
        fullWidth
        PaperProps={{
          sx: {
            background: "linear-gradient(135deg, #0a0a0f 0%, #1a0a2e 50%, #0f1a2e 100%)",
            border: "2px solid transparent",
            borderImage: "linear-gradient(90deg, #ff00ff, #00ffff, #ff00ff) 1",
            borderRadius: 0,
            clipPath: "polygon(0 0, calc(100% - 15px) 0, 100% 15px, 100% 100%, 15px 100%, 0 calc(100% - 15px))",
          }
        }}
      >
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 2, borderBottom: "1px solid rgba(0, 255, 255, 0.3)" }}>
          <Box
            sx={{
              width: 48,
              height: 48,
              background: "linear-gradient(135deg, #ff00ff 0%, #00ffff 100%)",
              clipPath: "polygon(50% 0%, 100% 25%, 100% 75%, 50% 100%, 0% 75%, 0% 25%)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              boxShadow: "0 0 20px rgba(255, 0, 255, 0.5)",
            }}
          >
            <LanIcon sx={{ color: "#0a0a0f", fontSize: 28 }} />
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography variant="h5" sx={{ fontWeight: 700, fontFamily: "'Orbitron', monospace", color: "#00ffff" }}>
              🎯 Setup Guide: Fuzzing Remote Targets
            </Typography>
            <Typography variant="body2" sx={{ color: "rgba(0, 255, 255, 0.7)" }}>
              How to target software running on VMs or air-gapped environments
            </Typography>
          </Box>
          <IconButton onClick={() => setShowSetupGuide(false)} sx={{ color: "#ff00ff", "&:hover": { background: "rgba(255, 0, 255, 0.1)" } }}>
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        
        <DialogContent sx={{ py: 3 }}>
          {/* Quick Overview */}
          <Alert 
            severity="info" 
            sx={{ 
              mb: 3, 
              background: "rgba(0, 255, 255, 0.1)", 
              border: "1px solid #00ffff",
              "& .MuiAlert-icon": { color: "#00ffff" },
            }}
          >
            <Typography variant="body2" sx={{ color: "#fff" }}>
              <strong style={{ color: "#00ffff" }}>TL;DR:</strong> The Agentic Fuzzer runs in your browser and sends HTTP requests to any accessible URL.
              To fuzz software on another VM, just make sure the target is reachable via HTTP/HTTPS and enter its IP address.
            </Typography>
          </Alert>

          {/* Network Diagram */}
          <Paper sx={{ p: 3, mb: 3, bgcolor: "rgba(0, 255, 255, 0.05)", border: "1px solid rgba(0, 255, 255, 0.3)" }}>
            <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: "#00ffff", fontFamily: "'Orbitron', monospace" }}>
              <RouterIcon sx={{ color: "#00ffff" }} />
              Network Setup Overview
            </Typography>
            <Box sx={{ 
              display: "flex", 
              alignItems: "center", 
              justifyContent: "center", 
              gap: 2, 
              my: 3,
              flexWrap: "wrap",
            }}>
              {/* Your PC */}
              <Box sx={{ textAlign: "center" }}>
                <Box sx={{ 
                  width: 80, 
                  height: 80, 
                  borderRadius: 2, 
                  bgcolor: alpha(theme.palette.success.main, 0.2),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: `2px solid ${theme.palette.success.main}`,
                  mb: 1,
                }}>
                  <ComputerIcon sx={{ fontSize: 40, color: theme.palette.success.main }} />
                </Box>
                <Typography variant="caption" fontWeight={600}>Your PC/VM</Typography>
                <Typography variant="caption" display="block" color="text.secondary">
                  (Running VRAgent)
                </Typography>
                <Chip label="192.168.1.10" size="small" sx={{ mt: 0.5 }} />
              </Box>

              {/* Arrow */}
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                <Typography variant="caption" color="text.secondary">HTTP Requests</Typography>
                <Box sx={{ fontSize: 32, color: theme.palette.primary.main }}>→→→</Box>
              </Box>

              {/* Target VM */}
              <Box sx={{ textAlign: "center" }}>
                <Box sx={{ 
                  width: 80, 
                  height: 80, 
                  borderRadius: 2, 
                  bgcolor: alpha(theme.palette.error.main, 0.2),
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  border: `2px solid ${theme.palette.error.main}`,
                  mb: 1,
                }}>
                  <SecurityIcon sx={{ fontSize: 40, color: theme.palette.error.main }} />
                </Box>
                <Typography variant="caption" fontWeight={600}>Target VM</Typography>
                <Typography variant="caption" display="block" color="text.secondary">
                  (Software to test)
                </Typography>
                <Chip label="192.168.1.50" size="small" color="error" sx={{ mt: 0.5 }} />
              </Box>
            </Box>
          </Paper>

          {/* Step by Step Guide */}
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LightbulbIcon color="warning" />
            Step-by-Step Setup
          </Typography>
          
          <Stepper orientation="vertical" activeStep={-1} sx={{ mb: 3 }}>
            <Step active>
              <StepLabel StepIconProps={{ sx: { color: theme.palette.primary.main } }}>
                <Typography variant="subtitle1" fontWeight={600}>Find the Target VM's IP Address</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="text.secondary" paragraph>
                  On the Windows VM running the software you want to test:
                </Typography>
                <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 1, fontFamily: "monospace", mb: 2 }}>
                  <Typography variant="body2" sx={{ color: "#4fc3f7" }}>
                    # Open Command Prompt and run:
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#fff" }}>
                    ipconfig
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#888", mt: 1 }}>
                    # Look for "IPv4 Address" - e.g., 192.168.1.50
                  </Typography>
                </Paper>
                <Typography variant="body2" color="text.secondary">
                  For VMware/VirtualBox: Use "Bridged" or "Host-Only" network adapter for local testing.
                </Typography>
              </Box>
            </Step>

            <Step active>
              <StepLabel>
                <Typography variant="subtitle1" fontWeight={600}>Start a Web Server on the Target</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="text.secondary" paragraph>
                  If testing a web application, ensure it's running. If testing a non-web app, you can expose it via a simple HTTP wrapper.
                </Typography>
                <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 1, fontFamily: "monospace", mb: 2 }}>
                  <Typography variant="body2" sx={{ color: "#4fc3f7" }}>
                    # Example: Python simple server on target VM
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#fff" }}>
                    python -m http.server 8080 --bind 0.0.0.0
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#888", mt: 1 }}>
                    # Or for a PHP app in XAMPP, it's usually on port 80
                  </Typography>
                </Paper>
                <Alert severity="warning" sx={{ mt: 1 }}>
                  Make sure Windows Firewall allows incoming connections on the port (e.g., 8080)
                </Alert>
              </Box>
            </Step>

            <Step active>
              <StepLabel>
                <Typography variant="subtitle1" fontWeight={600}>Configure Firewall on Target VM</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="text.secondary" paragraph>
                  Allow the fuzzer to reach the target:
                </Typography>
                <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 1, fontFamily: "monospace", mb: 2 }}>
                  <Typography variant="body2" sx={{ color: "#4fc3f7" }}>
                    # Windows PowerShell (Run as Admin) on TARGET VM:
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#fff" }}>
                    New-NetFirewallRule -DisplayName "Allow Fuzzer" -Direction Inbound -Port 8080 -Protocol TCP -Action Allow
                  </Typography>
                </Paper>
                <Typography variant="body2" color="text.secondary">
                  Or temporarily disable Windows Firewall for testing (Control Panel → Windows Defender Firewall → Turn off)
                </Typography>
              </Box>
            </Step>

            <Step active>
              <StepLabel>
                <Typography variant="subtitle1" fontWeight={600}>Test Connectivity</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="text.secondary" paragraph>
                  From your PC (where VRAgent runs), verify you can reach the target:
                </Typography>
                <Paper sx={{ p: 2, bgcolor: "#1e1e1e", borderRadius: 1, fontFamily: "monospace", mb: 2 }}>
                  <Typography variant="body2" sx={{ color: "#4fc3f7" }}>
                    # Test ping connectivity:
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#fff" }}>
                    ping 192.168.1.50
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#4fc3f7", mt: 1 }}>
                    # Test HTTP connectivity (use browser or curl):
                  </Typography>
                  <Typography variant="body2" sx={{ color: "#fff" }}>
                    curl http://192.168.1.50:8080
                  </Typography>
                </Paper>
                <Typography variant="body2" color="text.secondary">
                  If you get a response, you're ready to fuzz!
                </Typography>
              </Box>
            </Step>

            <Step active>
              <StepLabel>
                <Typography variant="subtitle1" fontWeight={600}>Enter the Target URL</Typography>
              </StepLabel>
              <Box sx={{ pl: 4, pb: 2 }}>
                <Typography variant="body2" color="text.secondary" paragraph>
                  In the Target URL field, enter the full URL to your target:
                </Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.1), borderRadius: 1, mb: 2 }}>
                  <Typography variant="body2" fontWeight={600} sx={{ mb: 1 }}>Example URLs:</Typography>
                  <Typography variant="body2" fontFamily="monospace">• http://192.168.1.50:8080/</Typography>
                  <Typography variant="body2" fontFamily="monospace">• http://192.168.1.50:8080/api/login</Typography>
                  <Typography variant="body2" fontFamily="monospace">• http://192.168.1.50/vulnerable-app/index.php</Typography>
                  <Typography variant="body2" fontFamily="monospace">• http://target-vm-hostname:3000/api/users</Typography>
                </Paper>
                <Alert severity="success">
                  Click "Start Agentic Fuzzing" and let the AI discover vulnerabilities automatically!
                </Alert>
              </Box>
            </Step>
          </Stepper>

          {/* Pro Tips */}
          <Paper sx={{ p: 2.5, bgcolor: alpha(theme.palette.warning.main, 0.08), border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`, borderRadius: 2 }}>
            <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, color: theme.palette.warning.main }}>
              <LightbulbIcon />
              Pro Tips for Air-Gapped Testing
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" paragraph>
                  <strong>🔒 True Air-Gap?</strong> If the target has NO network access, you'll need to:
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="success" /></ListItemIcon>
                    <ListItemText primary="Create an isolated virtual network" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="success" /></ListItemIcon>
                    <ListItemText primary="Put both VMs on the same Host-Only network" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="success" /></ListItemIcon>
                    <ListItemText primary="Disable internet on both adapters" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                </List>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="body2" paragraph>
                  <strong>⚡ Performance Tips:</strong>
                </Typography>
                <List dense>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="info" /></ListItemIcon>
                    <ListItemText primary="Start with 'Quick' depth for initial recon" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="info" /></ListItemIcon>
                    <ListItemText primary="Use 'Thorough' for full security audit" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                  <ListItem sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 32 }}><CheckCircleIcon fontSize="small" color="info" /></ListItemIcon>
                    <ListItemText primary="Save reports for documentation" primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                </List>
              </Grid>
            </Grid>
          </Paper>
        </DialogContent>
        
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setShowSetupGuide(false)}>Close</Button>
          <Button 
            variant="contained" 
            onClick={() => setShowSetupGuide(false)}
            startIcon={<PlayArrowIcon />}
          >
            Got it, Let's Fuzz!
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* IP Renewal Needed Dialog */}
      <Dialog 
        open={ipRenewalPending} 
        onClose={() => {}}
        disableEscapeKeyDown
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            background: "linear-gradient(135deg, #0a0a0f 0%, #1a2e0a 50%, #0f2e1a 100%)",
            border: "2px solid #4caf50",
            boxShadow: "0 0 30px rgba(76, 175, 80, 0.3)",
          }
        }}
      >
        <DialogTitle sx={{ 
          display: "flex", 
          alignItems: "center", 
          gap: 2, 
          borderBottom: "1px solid rgba(76, 175, 80, 0.3)",
          fontFamily: "'Orbitron', monospace",
        }}>
          <RouterIcon sx={{ color: "#4caf50" }} />
          <Typography sx={{ fontFamily: "'Orbitron', monospace", color: "#4caf50" }}>
            IP Renewal Required
          </Typography>
        </DialogTitle>
        <DialogContent sx={{ py: 3 }}>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <Typography variant="body2">
              <strong>🥷 Stealth Mode:</strong> To avoid detection, please release and renew your IP address now.
            </Typography>
          </Alert>
          
          <Typography variant="body1" gutterBottom>
            Open a <strong>Command Prompt (Admin)</strong> and run:
          </Typography>
          
          <Paper 
            sx={{ 
              p: 2, 
              mt: 2, 
              mb: 2, 
              bgcolor: 'rgba(0,0,0,0.5)', 
              fontFamily: 'monospace',
              borderRadius: 1,
            }}
          >
            <code style={{ color: '#00ff00' }}>
              ipconfig /release && ipconfig /renew
            </code>
            <IconButton 
              size="small" 
              sx={{ ml: 2, color: '#4caf50' }}
              onClick={() => navigator.clipboard.writeText('ipconfig /release && ipconfig /renew')}
            >
              <ContentCopyIcon fontSize="small" />
            </IconButton>
          </Paper>
          
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
            This releases your current IP lease and obtains a new IP address from your router/DHCP server, 
            making your scan requests appear to come from a different source.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button 
            variant="contained" 
            color="success"
            onClick={() => {
              setIpRenewalPending(false);
              // Could call an API to signal renewal done and continue
            }}
            startIcon={<CheckCircleIcon />}
          >
            IP Renewed - Continue Scan
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* Saved Reports Dialog */}
      <Dialog 
        open={showReportsPanel} 
        onClose={() => {
          setShowReportsPanel(false);
          setSelectedSavedReport(null);
        }}
        maxWidth="lg"
        fullWidth
        PaperProps={{
          sx: {
            background: "linear-gradient(135deg, #0a0a0f 0%, #1a0a2e 50%, #0f1a2e 100%)",
            border: "2px solid transparent",
            borderImage: "linear-gradient(90deg, #ff9800, #00ffff, #ff9800) 1",
            minHeight: "60vh",
          }
        }}
      >
        <DialogTitle sx={{ 
          display: "flex", 
          alignItems: "center", 
          gap: 2,
          borderBottom: "1px solid rgba(255, 152, 0, 0.3)",
          fontFamily: "'Orbitron', monospace",
        }}>
          <HistoryIcon sx={{ color: "#ff9800" }} />
          <Typography variant="h6" component="span" sx={{ fontFamily: "'Orbitron', monospace", color: "#ff9800" }}>
            Saved Fuzzing Reports
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <IconButton onClick={() => loadSavedReports()} disabled={isLoadingReports}>
            {isLoadingReports ? <CircularProgress size={20} /> : <RefreshIcon sx={{ color: "#00ffff" }} />}
          </IconButton>
          <IconButton onClick={() => { setShowReportsPanel(false); setSelectedSavedReport(null); }}>
            <CloseIcon sx={{ color: "#ff00ff" }} />
          </IconButton>
        </DialogTitle>
        <DialogContent sx={{ display: "flex", gap: 2, p: 2 }}>
          {/* Reports List */}
          <Box sx={{ 
            width: selectedSavedReport ? "40%" : "100%", 
            transition: "width 0.3s",
            borderRight: selectedSavedReport ? "1px solid rgba(255,255,255,0.1)" : "none",
            pr: selectedSavedReport ? 2 : 0,
          }}>
            {isLoadingReports ? (
              <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
                <CircularProgress />
              </Box>
            ) : savedReports.length === 0 ? (
              <Box sx={{ textAlign: "center", p: 4 }}>
                <AssessmentIcon sx={{ fontSize: 60, color: "rgba(255,255,255,0.2)", mb: 2 }} />
                <Typography color="text.secondary">
                  No saved reports yet. Run a fuzzing scan and it will be saved automatically!
                </Typography>
              </Box>
            ) : (
              <List>
                {savedReports.map((report) => (
                  <ListItem
                    key={report.id}
                    sx={{
                      mb: 1,
                      bgcolor: selectedSavedReport?.id === report.id ? "rgba(0, 255, 255, 0.1)" : "rgba(255,255,255,0.02)",
                      borderRadius: 1,
                      border: selectedSavedReport?.id === report.id ? "1px solid #00ffff" : "1px solid rgba(255,255,255,0.1)",
                      "&:hover": {
                        bgcolor: "rgba(255, 152, 0, 0.1)",
                        border: "1px solid rgba(255, 152, 0, 0.3)",
                      },
                    }}
                    secondaryAction={
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <Tooltip title="View Report">
                          <IconButton 
                            size="small" 
                            onClick={() => viewSavedReport(report.id)}
                            disabled={viewingReportId === report.id}
                          >
                            {viewingReportId === report.id ? (
                              <CircularProgress size={16} />
                            ) : (
                              <VisibilityIcon sx={{ color: "#00bfff" }} />
                            )}
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete Report">
                          <IconButton 
                            size="small" 
                            onClick={() => deleteSavedReport(report.id)}
                          >
                            <DeleteIcon sx={{ color: "#ff4444" }} />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    }
                  >
                    <ListItemIcon>
                      <AssessmentIcon sx={{ color: "#ff9800" }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography variant="body1" sx={{ color: "#fff", fontWeight: "bold" }}>
                          {report.title || `Scan ${report.id}`}
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="caption" sx={{ color: "#00ffff", display: "block" }}>
                            {report.target_url}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {report.completed_at ? new Date(report.completed_at).toLocaleString() : 'In progress'} • {report.findings?.total || 0} findings
                          </Typography>
                          {report.findings && (
                            <Box sx={{ display: "flex", gap: 0.5, mt: 0.5 }}>
                              {report.findings.critical > 0 && (
                                <Chip label={`${report.findings.critical} Critical`} size="small" color="error" sx={{ fontSize: "0.65rem", height: 18 }} />
                              )}
                              {report.findings.high > 0 && (
                                <Chip label={`${report.findings.high} High`} size="small" sx={{ fontSize: "0.65rem", height: 18, bgcolor: "#ff5722", color: "#fff" }} />
                              )}
                              {report.findings.medium > 0 && (
                                <Chip label={`${report.findings.medium} Medium`} size="small" color="warning" sx={{ fontSize: "0.65rem", height: 18 }} />
                              )}
                            </Box>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
          
          {/* Report Detail View */}
          {selectedSavedReport && (
            <Box sx={{ 
              width: "60%", 
              overflow: "auto",
              pl: 2,
            }}>
              <Typography variant="h6" sx={{ color: "#00ffff", mb: 2, fontFamily: "'Orbitron', monospace" }}>
                {selectedSavedReport.title || `Fuzzing Report #${selectedSavedReport.id}`}
              </Typography>
              
              {selectedSavedReport.target_url && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary">Target</Typography>
                  <Typography variant="body2" sx={{ fontFamily: "monospace", color: "#ff9800" }}>
                    {selectedSavedReport.target_url}
                  </Typography>
                </Box>
              )}
              
              {(selectedSavedReport.completed_at || selectedSavedReport.created_at) && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary">Date</Typography>
                  <Typography variant="body2">
                    {new Date(selectedSavedReport.completed_at || selectedSavedReport.created_at).toLocaleString()}
                  </Typography>
                </Box>
              )}
              
              {/* Findings Summary */}
              {selectedSavedReport.findings_summary && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="caption" color="text.secondary">Findings Summary</Typography>
                  <Box sx={{ display: "flex", gap: 1, mt: 0.5, flexWrap: "wrap" }}>
                    {selectedSavedReport.findings_summary.critical > 0 && (
                      <Chip label={`${selectedSavedReport.findings_summary.critical} Critical`} size="small" color="error" />
                    )}
                    {selectedSavedReport.findings_summary.high > 0 && (
                      <Chip label={`${selectedSavedReport.findings_summary.high} High`} size="small" sx={{ bgcolor: "#ff5722", color: "#fff" }} />
                    )}
                    {selectedSavedReport.findings_summary.medium > 0 && (
                      <Chip label={`${selectedSavedReport.findings_summary.medium} Medium`} size="small" color="warning" />
                    )}
                    {selectedSavedReport.findings_summary.low > 0 && (
                      <Chip label={`${selectedSavedReport.findings_summary.low} Low`} size="small" color="info" />
                    )}
                    {selectedSavedReport.findings_summary.info > 0 && (
                      <Chip label={`${selectedSavedReport.findings_summary.info} Info`} size="small" />
                    )}
                  </Box>
                </Box>
              )}
              
              <Divider sx={{ my: 2 }} />
              
              {/* Executive Summary */}
              {selectedSavedReport.executive_summary && (
                <ReportSection 
                  title="Executive Summary" 
                  data={selectedSavedReport.executive_summary}
                  color="#00ffff"
                  icon={<DescriptionIcon sx={{ fontSize: 18 }} />}
                />
              )}
              
              {/* AI Report - this contains the main assessment data */}
              {selectedSavedReport.ai_report && (
                <Box sx={{ mt: 2 }}>
                  {Object.entries(selectedSavedReport.ai_report).map(([key, value]) => (
                    <ReportSection 
                      key={key}
                      title={key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                      data={value}
                      color={
                        key.includes('risk') || key.includes('critical') ? "#ff6b6b" :
                        key.includes('summary') || key.includes('overview') ? "#00bfff" :
                        key.includes('remediation') ? "#00ff88" :
                        key.includes('compliance') ? "#ff00ff" :
                        "#6b8e9f"
                      }
                    />
                  ))}
                </Box>
              )}
              
              {/* Correlation Analysis */}
              {selectedSavedReport.correlation_analysis && (
                <ReportSection 
                  title="Correlation Analysis" 
                  data={selectedSavedReport.correlation_analysis}
                  color="#9c27b0"
                  icon={<AccountTreeIcon sx={{ fontSize: 18 }} />}
                />
              )}
              
              {/* Detailed Findings */}
              {Array.isArray(selectedSavedReport.findings) && selectedSavedReport.findings.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Typography variant="subtitle1" sx={{ color: "#ff4444", mb: 1, fontWeight: "bold" }}>
                    Detailed Findings ({selectedSavedReport.findings.length})
                  </Typography>
                  {selectedSavedReport.findings.slice(0, 10).map((finding: any, i: number) => (
                    <Box 
                      key={i} 
                      sx={{ 
                        p: 1, 
                        mb: 1, 
                        bgcolor: "rgba(255,0,0,0.05)", 
                        borderRadius: 1,
                        borderLeft: `3px solid ${finding.severity === 'critical' ? '#ff0000' : finding.severity === 'high' ? '#ff5722' : '#ff9800'}`,
                      }}
                    >
                      <Typography variant="body2" fontWeight="bold">
                        {finding.title || finding.type || `Finding ${i + 1}`}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {finding.description || finding.details}
                      </Typography>
                      <Chip 
                        label={finding.severity || 'info'} 
                        size="small" 
                        sx={{ ml: 1, fontSize: "0.65rem", height: 18 }}
                        color={finding.severity === 'critical' ? 'error' : finding.severity === 'high' ? 'warning' : 'default'}
                      />
                    </Box>
                  ))}
                  {selectedSavedReport.findings.length > 10 && (
                    <Typography variant="caption" color="text.secondary">
                      And {selectedSavedReport.findings.length - 10} more findings...
                    </Typography>
                  )}
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2, borderTop: "1px solid rgba(255,255,255,0.1)" }}>
          <Button onClick={() => { setShowReportsPanel(false); setSelectedSavedReport(null); }}>
            Close
          </Button>
        </DialogActions>
      </Dialog>
      
      <Grid container spacing={3}>
        {/* Configuration Panel */}
        <Grid item xs={12} md={4}>
          <Card sx={{
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(0, 255, 255, 0.3)",
            backdropFilter: "blur(10px)",
            "& .MuiTypography-root": { color: "#fff" },
            "& .MuiInputLabel-root": { color: "rgba(0, 255, 255, 0.7)" },
            "& .MuiOutlinedInput-root": {
              color: "#fff",
              "& fieldset": { borderColor: "rgba(0, 255, 255, 0.3)" },
              "&:hover fieldset": { borderColor: "#00ffff" },
              "&.Mui-focused fieldset": { borderColor: "#ff00ff" },
            },
            "& .MuiSelect-icon": { color: "#00ffff" },
          }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#00ffff !important" }}>
                <TuneIcon sx={{ color: "#00ffff" }} />
                Configuration
              </Typography>
              
              {/* Target URL */}
              <TextField
                fullWidth
                label="Target URL"
                placeholder="https://example.com/api/endpoint"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                margin="normal"
                disabled={isRunning}
              />
              
              {/* Method */}
              <FormControl fullWidth margin="normal">
                <InputLabel>HTTP Method</InputLabel>
                <Select
                  value={method}
                  label="HTTP Method"
                  onChange={(e) => setMethod(e.target.value)}
                  disabled={isRunning}
                >
                  <MenuItem value="AUTO">
                    <em>AUTO</em> - Detect from JavaScript
                  </MenuItem>
                  <MenuItem value="GET">GET</MenuItem>
                  <MenuItem value="POST">POST</MenuItem>
                  <MenuItem value="PUT">PUT</MenuItem>
                  <MenuItem value="DELETE">DELETE</MenuItem>
                  <MenuItem value="PATCH">PATCH</MenuItem>
                </Select>
              </FormControl>
              
              {/* Headers */}
              <TextField
                fullWidth
                label="Headers (one per line)"
                placeholder="Authorization: Bearer token&#10;Content-Type: application/json"
                value={headers}
                onChange={(e) => setHeaders(e.target.value)}
                margin="normal"
                multiline
                rows={3}
                disabled={isRunning}
              />
              
              {/* Body */}
              <TextField
                fullWidth
                label="Request Body"
                placeholder='{"key": "FUZZ"}'
                value={body}
                onChange={(e) => setBody(e.target.value)}
                margin="normal"
                multiline
                rows={3}
                disabled={isRunning}
              />
              
              <Divider sx={{ my: 2 }} />
              
              {/* Presets */}
              <Typography variant="subtitle2" gutterBottom>
                Quick Presets
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                {presets.map((preset) => (
                  <Chip
                    key={preset.id}
                    label={preset.name}
                    onClick={() => applyPreset(preset.id)}
                    color={selectedPreset === preset.id ? "primary" : "default"}
                    variant={selectedPreset === preset.id ? "filled" : "outlined"}
                    size="small"
                    disabled={isRunning}
                  />
                ))}
              </Box>
              
              {/* Depth */}
              <FormControl fullWidth margin="normal">
                <InputLabel>Scan Depth</InputLabel>
                <Select
                  value={depth}
                  label="Scan Depth"
                  onChange={(e) => setDepth(e.target.value)}
                  disabled={isRunning}
                >
                  <MenuItem value="minimal">Minimal (25 iterations) - Quick check</MenuItem>
                  <MenuItem value="quick">Light (50 iterations) - CI/CD friendly</MenuItem>
                  <MenuItem value="normal">Standard (150 iterations) - Balanced</MenuItem>
                  <MenuItem value="thorough">Thorough (500 iterations) - Deep analysis</MenuItem>
                  <MenuItem value="aggressive">Exhaustive (1500 iterations) - Maximum coverage</MenuItem>
                </Select>
              </FormControl>
              
              {/* Max Iterations */}
              <TextField
                fullWidth
                type="number"
                label="Max Iterations"
                value={maxIterations}
                onChange={(e) => setMaxIterations(parseInt(e.target.value) || 50)}
                margin="normal"
                inputProps={{ min: 5, max: 500 }}
                disabled={isRunning}
                helperText="Override the preset depth with custom iteration count"
              />
              
              {/* Stealth Mode Section */}
              <Box sx={{ 
                mt: 2, 
                p: 2, 
                border: stealthMode ? '2px solid' : '1px solid',
                borderColor: stealthMode ? 'warning.main' : 'divider',
                borderRadius: 2,
                bgcolor: stealthMode ? 'warning.dark' : 'transparent',
                transition: 'all 0.3s ease'
              }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={stealthMode}
                      onChange={(e) => setStealthMode(e.target.checked)}
                      disabled={isRunning}
                      color="warning"
                    />
                  }
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: stealthMode ? 'bold' : 'normal' }}>
                        🥷 Stealth Mode
                      </Typography>
                      {stealthMode && (
                        <Chip 
                          label="ACTIVE" 
                          size="small" 
                          color="warning" 
                          sx={{ height: 20, fontSize: '0.7rem' }}
                        />
                      )}
                    </Box>
                  }
                />
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 4, mb: stealthMode ? 2 : 0 }}>
                  Evade detection with randomized timing, rotating user-agents, and periodic pauses
                </Typography>
                
                {stealthMode && (
                  <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <TextField
                        type="number"
                        label="Min Delay (sec)"
                        value={stealthDelayMin}
                        onChange={(e) => setStealthDelayMin(parseFloat(e.target.value) || 2.0)}
                        size="small"
                        inputProps={{ min: 0.5, max: 30, step: 0.5 }}
                        disabled={isRunning}
                        sx={{ flex: 1 }}
                        helperText="Minimum delay between requests"
                      />
                      <TextField
                        type="number"
                        label="Max Delay (sec)"
                        value={stealthDelayMax}
                        onChange={(e) => setStealthDelayMax(parseFloat(e.target.value) || 5.0)}
                        size="small"
                        inputProps={{ min: 1, max: 60, step: 0.5 }}
                        disabled={isRunning}
                        sx={{ flex: 1 }}
                        helperText="Maximum delay between requests"
                      />
                    </Box>
                    <Box sx={{ display: 'flex', gap: 2 }}>
                      <TextField
                        type="number"
                        label="Requests Before Pause"
                        value={stealthRequestsBeforePause}
                        onChange={(e) => setStealthRequestsBeforePause(parseInt(e.target.value) || 10)}
                        size="small"
                        inputProps={{ min: 5, max: 100 }}
                        disabled={isRunning}
                        sx={{ flex: 1 }}
                        helperText="Take a longer pause every N requests"
                      />
                      <TextField
                        type="number"
                        label="Pause Duration (sec)"
                        value={stealthPauseDuration}
                        onChange={(e) => setStealthPauseDuration(parseFloat(e.target.value) || 30.0)}
                        size="small"
                        inputProps={{ min: 10, max: 300 }}
                        disabled={isRunning}
                        sx={{ flex: 1 }}
                        helperText="Duration of periodic pause"
                      />
                    </Box>
                    
                    {/* IP Renewal Option */}
                    <Box sx={{ 
                      p: 2, 
                      borderRadius: 1, 
                      bgcolor: stealthIpRenewalEnabled ? alpha(theme.palette.success.main, 0.1) : 'transparent',
                      border: stealthIpRenewalEnabled ? `1px solid ${theme.palette.success.main}` : '1px solid transparent',
                    }}>
                      <FormControlLabel
                        control={
                          <Checkbox
                            checked={stealthIpRenewalEnabled}
                            onChange={(e) => setStealthIpRenewalEnabled(e.target.checked)}
                            size="small"
                            disabled={isRunning}
                          />
                        }
                        label={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <RouterIcon sx={{ fontSize: 18, color: 'success.main' }} />
                            <Typography variant="body2">
                              IP Release/Renew Prompts
                            </Typography>
                          </Box>
                        }
                      />
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', ml: 4 }}>
                        Periodically prompt you to release/renew your IP address to avoid detection
                      </Typography>
                      {stealthIpRenewalEnabled && (
                        <TextField
                          type="number"
                          label="Requests Between IP Renewals"
                          value={stealthIpRenewalInterval}
                          onChange={(e) => setStealthIpRenewalInterval(parseInt(e.target.value) || 50)}
                          size="small"
                          inputProps={{ min: 20, max: 500 }}
                          disabled={isRunning}
                          sx={{ mt: 2, width: '100%' }}
                          helperText="Prompt for IP renewal every N requests"
                        />
                      )}
                    </Box>
                    
                    <Alert severity="info" sx={{ mt: 1 }}>
                      <Typography variant="caption">
                        <strong>Stealth features:</strong> Random User-Agent rotation, varied Accept headers, 
                        randomized timing between min/max delay, periodic longer pauses to avoid rate limiting
                        {stealthIpRenewalEnabled && ', IP release/renew prompts'}
                      </Typography>
                    </Alert>
                  </Box>
                )}
              </Box>
              
              <Divider sx={{ my: 2 }} />
              
              {/* Techniques */}
              <Typography variant="subtitle2" gutterBottom>
                Techniques (leave empty for all)
              </Typography>
              {Object.entries(techniquesByCategory).map(([category, techs]) => (
                <Accordion key={category} defaultExpanded={false} disabled={isRunning}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">{category}</Typography>
                    <Chip 
                      size="small" 
                      label={techs.filter(t => selectedTechniques.includes(t.id)).length}
                      sx={{ ml: 1 }}
                    />
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ display: "flex", flexDirection: "column", gap: 0.5 }}>
                      {techs.map((tech) => (
                        <FormControlLabel
                          key={tech.id}
                          control={
                            <Checkbox
                              checked={selectedTechniques.includes(tech.id)}
                              onChange={() => toggleTechnique(tech.id)}
                              size="small"
                            />
                          }
                          label={<Typography variant="body2">{tech.name}</Typography>}
                        />
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
              
              <Divider sx={{ my: 2 }} />
              
              {/* Action Buttons */}
              <Box sx={{ display: "flex", gap: 2 }}>
                {!isRunning ? (
                  <Button
                    fullWidth
                    variant="contained"
                    color="primary"
                    startIcon={<PlayArrowIcon />}
                    onClick={startFuzzing}
                    disabled={!targetUrl}
                  >
                    Start Agentic Fuzzing
                  </Button>
                ) : (
                  <Button
                    fullWidth
                    variant="contained"
                    color="error"
                    startIcon={<StopIcon />}
                    onClick={stopFuzzing}
                  >
                    Stop
                  </Button>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>
        
        {/* Main Content */}
        <Grid item xs={12} md={8}>
          {/* Status Card */}
          <Card sx={{ 
            mb: 2,
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(15, 26, 46, 0.8) 100%)",
            border: "1px solid rgba(0, 255, 136, 0.3)",
          }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Typography variant="h6" sx={{ fontFamily: "'Orbitron', monospace", color: "#00ff88" }}>Status</Typography>
                {isRunning && <CircularProgress size={24} sx={{ color: "#00ff88" }} />}
                <Chip
                  label={isRunning ? "RUNNING" : "IDLE"}
                  size="small"
                  sx={{
                    background: isRunning ? "rgba(0, 255, 136, 0.2)" : "rgba(128, 128, 128, 0.2)",
                    border: isRunning ? "1px solid #00ff88" : "1px solid rgba(128, 128, 128, 0.5)",
                    color: isRunning ? "#00ff88" : "#888",
                    fontFamily: "'Orbitron', monospace",
                    fontWeight: "bold",
                  }}
                />
              </Box>
              
              {/* Progress - Use detailedProgress for accurate tracking */}
              {(isRunning || progress > 0 || (detailedProgress && detailedProgress.overall_progress > 0)) && (
                <Box sx={{ mb: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                    <Typography variant="body2" sx={{ color: "#00ffff", fontFamily: "monospace" }}>
                      Iteration {detailedProgress?.iteration || iteration} / {detailedProgress?.max_iterations || maxIter || maxIterations}
                    </Typography>
                    <Typography variant="body2" sx={{ color: "#ff00ff", fontFamily: "monospace" }}>
                      {Math.round(detailedProgress?.overall_progress || progress)}%
                    </Typography>
                  </Box>
                  <LinearProgress 
                    variant="determinate" 
                    value={detailedProgress?.overall_progress || progress}
                    sx={{ 
                      height: 8, 
                      borderRadius: 1,
                      bgcolor: "rgba(0, 255, 255, 0.1)",
                      "& .MuiLinearProgress-bar": {
                        background: "linear-gradient(90deg, #00ffff, #ff00ff)",
                      },
                    }}
                  />
                  
                  {/* Additional metrics when running */}
                  {detailedProgress && isRunning && (
                    <Box sx={{ display: "flex", gap: 2, mt: 1, flexWrap: "wrap" }}>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        📡 Requests: {detailedProgress.metrics?.requests_made || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        🎯 Findings: {detailedProgress.metrics?.findings_count || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        🔍 Endpoints: {detailedProgress.metrics?.endpoints_discovered || 0}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "text.secondary" }}>
                        ⚡ Techniques: {detailedProgress.metrics?.techniques_tested || 0}
                      </Typography>
                    </Box>
                  )}
                </Box>
              )}
              
              {/* ETA Display */}
              {eta && isRunning && !eta.is_complete && (
                <Box sx={{ 
                  mb: 2, 
                  p: 2, 
                  bgcolor: "rgba(0, 255, 255, 0.05)", 
                  borderRadius: 1,
                  border: "1px solid rgba(0, 255, 255, 0.3)",
                }}>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <ScheduleIcon sx={{ color: "#00ffff" }} />
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "#00ffff" }}>
                        Estimated Time
                      </Typography>
                    </Box>
                    <Tooltip title={`Confidence: ${eta.confidence} (based on historical scan data)`}>
                      <Chip 
                        label={eta.confidence} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(getConfidenceColor(eta.confidence), 0.2),
                          color: getConfidenceColor(eta.confidence),
                          fontWeight: 500,
                        }}
                      />
                    </Tooltip>
                  </Box>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <AccessTimeIcon sx={{ color: "#00ffff", fontSize: 20 }} />
                        <Typography variant="body2" sx={{ color: "rgba(255, 255, 255, 0.7)" }}>Remaining</Typography>
                        <Typography variant="h6" sx={{ fontFamily: "monospace", color: "#fff" }}>
                          {formatDuration(eta.time_remaining_seconds)}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <TimerIcon sx={{ color: theme.palette.text.secondary, fontSize: 20 }} />
                        <Typography variant="body2" color="text.secondary">Elapsed</Typography>
                        <Typography variant="h6" sx={{ fontFamily: "monospace" }}>
                          {formatDuration(eta.time_elapsed_seconds)}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <TrendingUpIcon sx={{ color: theme.palette.text.secondary, fontSize: 20 }} />
                        <Typography variant="body2" color="text.secondary">Est. Complete</Typography>
                        <Typography variant="h6" sx={{ fontFamily: "monospace" }}>
                          {formatCompletionTime(eta.estimated_completion_time)}
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Box sx={{ textAlign: "center" }}>
                        <BugReportIcon sx={{ color: theme.palette.text.secondary, fontSize: 20 }} />
                        <Typography variant="body2" color="text.secondary">Findings</Typography>
                        <Typography variant="h6" color="error.main">
                          {eta.findings_count}
                        </Typography>
                      </Box>
                    </Grid>
                  </Grid>
                  
                  {/* Phase Progress */}
                  <Box sx={{ mt: 2 }}>
                    <Box sx={{ display: "flex", justifyContent: "space-between", mb: 0.5 }}>
                      <Typography variant="caption" color="text.secondary">
                        Phase: {eta.current_phase.replace("_", " ")}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {Math.round(eta.overall_progress)}% overall
                      </Typography>
                    </Box>
                    <LinearProgress 
                      variant="determinate" 
                      value={eta.overall_progress}
                      sx={{ 
                        height: 4, 
                        borderRadius: 2,
                        bgcolor: alpha(theme.palette.info.main, 0.2),
                        '& .MuiLinearProgress-bar': {
                          bgcolor: theme.palette.info.main,
                        }
                      }}
                    />
                  </Box>
                </Box>
              )}
              
              {/* Enhanced Phase Timeline */}
              {detailedProgress && isRunning && detailedProgress.phase_timeline && detailedProgress.phase_timeline.length > 0 && (
                <Box sx={{ 
                  mb: 2, 
                  p: 2, 
                  bgcolor: "rgba(138, 43, 226, 0.05)", 
                  borderRadius: 1,
                  border: "1px solid rgba(138, 43, 226, 0.3)",
                }}>
                  <Typography variant="subtitle2" sx={{ mb: 2, color: "#8a2be2", fontWeight: 600 }}>
                    Scan Progress Timeline
                  </Typography>
                  
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {detailedProgress.phase_timeline.map((phase, index) => (
                      <Box 
                        key={phase.name} 
                        sx={{ 
                          display: "flex", 
                          alignItems: "center", 
                          gap: 1.5,
                          opacity: phase.status === "pending" ? 0.5 : 1,
                        }}
                      >
                        {/* Phase indicator */}
                        <Box sx={{ 
                          width: 24, 
                          height: 24, 
                          borderRadius: "50%", 
                          display: "flex", 
                          alignItems: "center", 
                          justifyContent: "center",
                          bgcolor: phase.status === "completed" ? "success.main" 
                            : phase.status === "in_progress" ? "info.main"
                            : phase.status === "error" ? "error.main"
                            : phase.status === "skipped" ? "grey.500"
                            : "grey.700",
                          color: "#fff",
                          fontSize: 12,
                        }}>
                          {phase.status === "completed" ? "✓" 
                            : phase.status === "in_progress" ? "●"
                            : phase.status === "error" ? "✗"
                            : phase.status === "skipped" ? "○"
                            : (index + 1)}
                        </Box>
                        
                        {/* Phase info */}
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body2" sx={{ 
                            fontWeight: phase.status === "in_progress" ? 600 : 400,
                            color: phase.status === "in_progress" ? "#00ffff" : "inherit",
                          }}>
                            {phase.label}
                          </Typography>
                          {phase.status === "in_progress" && phase.progress > 0 && (
                            <LinearProgress 
                              variant="determinate" 
                              value={phase.progress}
                              sx={{ 
                                height: 3, 
                                mt: 0.5,
                                borderRadius: 1,
                                bgcolor: "rgba(0, 255, 255, 0.1)",
                                "& .MuiLinearProgress-bar": {
                                  bgcolor: "#00ffff",
                                },
                              }}
                            />
                          )}
                        </Box>
                        
                        {/* Status chip */}
                        <Chip 
                          label={phase.status.replace("_", " ")} 
                          size="small"
                          sx={{ 
                            fontSize: 10,
                            height: 20,
                            bgcolor: phase.status === "completed" ? "rgba(76, 175, 80, 0.2)"
                              : phase.status === "in_progress" ? "rgba(0, 255, 255, 0.2)"
                              : phase.status === "error" ? "rgba(244, 67, 54, 0.2)"
                              : "rgba(128, 128, 128, 0.2)",
                            color: phase.status === "completed" ? "#4caf50"
                              : phase.status === "in_progress" ? "#00ffff"
                              : phase.status === "error" ? "#f44336"
                              : "#888",
                          }}
                        />
                      </Box>
                    ))}
                  </Box>
                  
                  {/* Metrics summary */}
                  {detailedProgress.metrics && (
                    <Box sx={{ 
                      mt: 2, 
                      pt: 2, 
                      borderTop: "1px solid rgba(138, 43, 226, 0.2)",
                      display: "flex",
                      justifyContent: "space-around",
                    }}>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h6" sx={{ color: "#00ffff", fontFamily: "monospace" }}>
                          {detailedProgress.metrics.requests_made}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Requests</Typography>
                      </Box>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h6" sx={{ color: "#ff00ff", fontFamily: "monospace" }}>
                          {detailedProgress.metrics.endpoints_discovered}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Endpoints</Typography>
                      </Box>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h6" sx={{ color: "#00ff88", fontFamily: "monospace" }}>
                          {detailedProgress.metrics.techniques_tested}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Techniques</Typography>
                      </Box>
                      <Box sx={{ textAlign: "center" }}>
                        <Typography variant="h6" sx={{ color: "#ff4444", fontFamily: "monospace" }}>
                          {detailedProgress.metrics.findings_count}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Findings</Typography>
                      </Box>
                    </Box>
                  )}
                </Box>
              )}
              
              {/* Phase & Technique */}
              <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                {currentPhase && (
                  <Chip
                    icon={getPhaseIcon(currentPhase)}
                    label={`Phase: ${currentPhase.replace("_", " ")}`}
                    variant="outlined"
                    color="primary"
                  />
                )}
                {currentTechnique && (
                  <Chip
                    icon={<SecurityIcon />}
                    label={`Technique: ${currentTechnique.replace("_", " ")}`}
                    variant="outlined"
                    color="secondary"
                  />
                )}
              </Box>
              
              {/* Summary */}
              {summary && (
                <Box sx={{ mt: 2, p: 2, bgcolor: alpha(theme.palette.success.main, 0.1), borderRadius: 2 }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                    <Typography variant="subtitle2">
                      <CheckCircleIcon sx={{ verticalAlign: "middle", mr: 1 }} />
                      Scan Complete
                    </Typography>
                    
                    {/* Save & Export Buttons */}
                    <Box sx={{ display: "flex", gap: 1 }}>
                      {!savedReportId && finalReport && (
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={isSavingReport ? <CircularProgress size={16} /> : <SaveIcon />}
                          onClick={saveReport}
                          disabled={isSavingReport}
                        >
                          {isSavingReport ? "Saving..." : "Save Report"}
                        </Button>
                      )}
                      {savedReportId && (
                        <Chip 
                          icon={<CheckCircleIcon />} 
                          label="Saved" 
                          color="success" 
                          size="small" 
                          variant="outlined"
                        />
                      )}
                    </Box>
                  </Box>
                  
                  <Grid container spacing={2}>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="body2" color="text.secondary">Requests</Typography>
                      <Typography variant="h6">{summary.total_requests}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="body2" color="text.secondary">Findings</Typography>
                      <Typography variant="h6" color="error">{summary.findings_count}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="body2" color="text.secondary">Duration</Typography>
                      <Typography variant="h6">{Math.round(summary.duration_seconds)}s</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="body2" color="text.secondary">Techniques</Typography>
                      <Typography variant="h6">{summary.techniques_used.length}</Typography>
                    </Grid>
                  </Grid>
                  
                  {/* Export Options */}
                  {(savedReportId || finalReport) && (
                    <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${alpha(theme.palette.success.main, 0.3)}` }}>
                      <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                        Export Report:
                      </Typography>
                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={isExporting ? <CircularProgress size={16} /> : <DescriptionIcon />}
                          onClick={() => exportReport("markdown")}
                          disabled={isExporting}
                          sx={{ textTransform: "none" }}
                        >
                          Markdown
                        </Button>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={isExporting ? <CircularProgress size={16} /> : <PictureAsPdfIcon />}
                          onClick={() => exportReport("pdf")}
                          disabled={isExporting}
                          sx={{ textTransform: "none" }}
                        >
                          PDF
                        </Button>
                        <Button
                          variant="outlined"
                          size="small"
                          startIcon={isExporting ? <CircularProgress size={16} /> : <ArticleIcon />}
                          onClick={() => exportReport("docx")}
                          disabled={isExporting}
                          sx={{ textTransform: "none" }}
                        >
                          Word
                        </Button>
                      </Box>
                    </Box>
                  )}
                </Box>
              )}
              
              {/* Detailed AI Report Section - Always show if finalReport exists */}
              {finalReport && (
                <Box sx={{ 
                  mt: 3, 
                  p: 2, 
                  bgcolor: "rgba(0, 150, 255, 0.05)", 
                  borderRadius: 2,
                  border: "1px solid rgba(0, 150, 255, 0.3)",
                }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                    <Typography variant="h6" sx={{ 
                      display: "flex", 
                      alignItems: "center", 
                      gap: 1, 
                      color: "#00bfff",
                      fontFamily: "'Orbitron', monospace",
                    }}>
                      <AssessmentIcon sx={{ color: "#00bfff" }} />
                      AI Security Assessment
                    </Typography>
                    
                    {/* Export Buttons - Always visible in report section */}
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                      {!savedReportId && (
                        <Button
                          variant="contained"
                          size="small"
                          color="primary"
                          startIcon={isSavingReport ? <CircularProgress size={16} /> : <SaveIcon />}
                          onClick={saveReport}
                          disabled={isSavingReport}
                          sx={{ textTransform: "none" }}
                        >
                          {isSavingReport ? "Saving..." : "Save"}
                        </Button>
                      )}
                      {savedReportId && (
                        <>
                          <Chip 
                            icon={<CheckCircleIcon />} 
                            label="Saved" 
                            color="success" 
                            size="small" 
                            variant="outlined"
                          />
                          <Button
                            variant="outlined"
                            size="small"
                            startIcon={isExporting ? <CircularProgress size={16} /> : <DescriptionIcon />}
                            onClick={() => exportReport("markdown")}
                            disabled={isExporting}
                            sx={{ textTransform: "none" }}
                          >
                            MD
                          </Button>
                          <Button
                            variant="outlined"
                            size="small"
                            startIcon={isExporting ? <CircularProgress size={16} /> : <PictureAsPdfIcon />}
                            onClick={() => exportReport("pdf")}
                            disabled={isExporting}
                            sx={{ textTransform: "none" }}
                          >
                            PDF
                          </Button>
                          <Button
                            variant="outlined"
                            size="small"
                            startIcon={isExporting ? <CircularProgress size={16} /> : <ArticleIcon />}
                            onClick={() => exportReport("docx")}
                            disabled={isExporting}
                            sx={{ textTransform: "none" }}
                          >
                            Word
                          </Button>
                        </>
                      )}
                    </Box>
                  </Box>
                  
                  {/* Show report content if it exists */}
                  {finalReport.report ? (
                    <>
                      {/* Report Metadata - Scan Statistics */}
                      {finalReport.report.report_metadata && (
                        <Box sx={{ 
                          mb: 2, 
                          p: 2, 
                          bgcolor: "rgba(0,0,0,0.3)", 
                          borderRadius: 1,
                          border: "1px solid rgba(0,150,255,0.2)"
                        }}>
                          <Typography variant="subtitle2" sx={{ color: "#00bfff", mb: 1.5, fontWeight: 600 }}>
                            📊 Scan Statistics
                          </Typography>
                          <Grid container spacing={2}>
                            <Grid item xs={6} sm={3}>
                              <Box sx={{ textAlign: "center", p: 1, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                                <Typography variant="h5" sx={{ color: "#4caf50", fontWeight: 700 }}>
                                  {finalReport.report.report_metadata.scan_summary?.targets_tested || 0}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">Targets Tested</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Box sx={{ textAlign: "center", p: 1, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                                <Typography variant="h5" sx={{ color: "#2196f3", fontWeight: 700 }}>
                                  {finalReport.report.report_metadata.scan_summary?.total_iterations || 0}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">Iterations</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Box sx={{ textAlign: "center", p: 1, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                                <Typography variant="h5" sx={{ color: "#ff9800", fontWeight: 700 }}>
                                  {finalReport.report.report_metadata.scan_summary?.passive_findings || 0}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">Passive Findings</Typography>
                              </Box>
                            </Grid>
                            <Grid item xs={6} sm={3}>
                              <Box sx={{ textAlign: "center", p: 1, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                                <Typography variant="h5" sx={{ color: "#f44336", fontWeight: 700 }}>
                                  {finalReport.report.report_metadata.scan_summary?.active_findings || 0}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">Active Findings</Typography>
                              </Box>
                            </Grid>
                          </Grid>
                        </Box>
                      )}
                      
                      {/* Detected Security Findings - from session_summary */}
                      {finalReport.session_summary?.findings && finalReport.session_summary.findings.length > 0 && (
                        <Box sx={{ 
                          mb: 2, 
                          p: 2, 
                          bgcolor: "rgba(255,0,0,0.1)", 
                          borderRadius: 1,
                          border: "2px solid rgba(255,68,68,0.5)"
                        }}>
                          <Typography variant="subtitle2" sx={{ color: "#ff4444", mb: 1.5, fontWeight: 600, display: "flex", alignItems: "center", gap: 1 }}>
                            <WarningIcon sx={{ fontSize: 20 }} />
                            🔴 Security Findings Detected ({finalReport.session_summary.findings.length} issues)
                          </Typography>
                          
                          {/* Severity Breakdown */}
                          <Box sx={{ display: "flex", gap: 2, mb: 2, flexWrap: "wrap" }}>
                            {(() => {
                              const findings = finalReport.session_summary.findings;
                              const critical = findings.filter((f: any) => f.severity?.toLowerCase() === "critical").length;
                              const high = findings.filter((f: any) => f.severity?.toLowerCase() === "high").length;
                              const medium = findings.filter((f: any) => f.severity?.toLowerCase() === "medium").length;
                              const low = findings.filter((f: any) => f.severity?.toLowerCase() === "low").length;
                              const info = findings.filter((f: any) => f.severity?.toLowerCase() === "info" || f.severity?.toLowerCase() === "informational").length;
                              
                              return (
                                <>
                                  {critical > 0 && (
                                    <Chip size="small" label={`${critical} Critical`} sx={{ bgcolor: "#dc143c", color: "white", fontWeight: 700 }} />
                                  )}
                                  {high > 0 && (
                                    <Chip size="small" label={`${high} High`} sx={{ bgcolor: "#ff4444", color: "white", fontWeight: 600 }} />
                                  )}
                                  {medium > 0 && (
                                    <Chip size="small" label={`${medium} Medium`} sx={{ bgcolor: "#ff9800", color: "white", fontWeight: 600 }} />
                                  )}
                                  {low > 0 && (
                                    <Chip size="small" label={`${low} Low`} sx={{ bgcolor: "#2196f3", color: "white" }} />
                                  )}
                                  {info > 0 && (
                                    <Chip size="small" label={`${info} Info`} sx={{ bgcolor: "#607d8b", color: "white" }} />
                                  )}
                                </>
                              );
                            })()}
                          </Box>
                          
                          {/* Finding List */}
                          <Box sx={{ maxHeight: 400, overflow: "auto" }}>
                            {finalReport.session_summary.findings.map((finding: any, idx: number) => (
                              <Paper 
                                key={idx} 
                                elevation={2}
                                sx={{ 
                                  p: 1.5, 
                                  mb: 1, 
                                  bgcolor: "rgba(0,0,0,0.3)",
                                  borderLeft: `4px solid ${
                                    finding.severity?.toLowerCase() === "critical" ? "#dc143c" :
                                    finding.severity?.toLowerCase() === "high" ? "#ff4444" :
                                    finding.severity?.toLowerCase() === "medium" ? "#ff9800" :
                                    finding.severity?.toLowerCase() === "low" ? "#2196f3" : "#607d8b"
                                  }`
                                }}
                              >
                                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", mb: 0.5 }}>
                                  <Typography variant="subtitle2" sx={{ fontWeight: 600, color: "white" }}>
                                    {finding.title || finding.name || finding.technique || "Finding"}
                                  </Typography>
                                  <Chip 
                                    size="small" 
                                    label={finding.severity || "Unknown"} 
                                    sx={{ 
                                      bgcolor: 
                                        finding.severity?.toLowerCase() === "critical" ? "#dc143c" :
                                        finding.severity?.toLowerCase() === "high" ? "#ff4444" :
                                        finding.severity?.toLowerCase() === "medium" ? "#ff9800" :
                                        finding.severity?.toLowerCase() === "low" ? "#2196f3" : "#607d8b",
                                      color: "white",
                                      fontSize: "0.7rem",
                                      height: 20
                                    }} 
                                  />
                                </Box>
                                <Typography variant="body2" sx={{ color: "text.secondary", fontSize: "0.85rem" }}>
                                  {finding.description || finding.details || "No description available"}
                                </Typography>
                                {finding.url && (
                                  <Typography variant="caption" sx={{ color: "#00bfff", display: "block", mt: 0.5 }}>
                                    📍 {finding.url}
                                  </Typography>
                                )}
                                {finding.technique && finding.technique !== finding.title && (
                                  <Typography variant="caption" sx={{ color: "#ffd700", display: "block" }}>
                                    🔧 Technique: {finding.technique}
                                  </Typography>
                                )}
                                {finding.evidence && (
                                  <Box sx={{ mt: 0.5, p: 0.5, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 0.5, maxHeight: 80, overflow: "auto" }}>
                                    <Typography variant="caption" sx={{ fontFamily: "monospace", color: "#aaa", whiteSpace: "pre-wrap" }}>
                                      {typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence, null, 2)}
                                    </Typography>
                                  </Box>
                                )}
                              </Paper>
                            ))}
                          </Box>
                        </Box>
                      )}
                      
                      {/* No findings alert */}
                      {(!finalReport.session_summary?.findings || finalReport.session_summary.findings.length === 0) && (
                        <Box sx={{ 
                          mb: 2, 
                          p: 2, 
                          bgcolor: "rgba(76,175,80,0.1)", 
                          borderRadius: 1,
                          border: "1px solid rgba(76,175,80,0.3)"
                        }}>
                          <Typography variant="subtitle2" sx={{ color: "#4caf50", display: "flex", alignItems: "center", gap: 1 }}>
                            <CheckCircleIcon sx={{ fontSize: 20 }} />
                            No exploitable vulnerabilities found during active fuzzing
                          </Typography>
                          <Typography variant="body2" sx={{ color: "text.secondary", mt: 0.5 }}>
                            The scan completed without discovering any exploitable vulnerabilities. Review the AI analysis below for passive findings and security recommendations.
                          </Typography>
                        </Box>
                      )}
                      
                      {/* Assessment Overview - common AI field */}
                      {(finalReport.report.assessment_overview || finalReport.report.assessmentOverview || finalReport.report.overview) && (
                        <ReportSection 
                          title="Assessment Overview" 
                          data={finalReport.report.assessment_overview || finalReport.report.assessmentOverview || finalReport.report.overview}
                          color="#00bfff"
                          icon={<AssessmentIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Executive Summary */}
                      {(finalReport.report.executive_summary || finalReport.report.summary || finalReport.report.executiveSummary) && (
                        <ReportSection 
                          title="Executive Summary" 
                          data={finalReport.report.executive_summary || finalReport.report.summary || finalReport.report.executiveSummary}
                          color="#00ffff"
                          icon={<DescriptionIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Key Metrics */}
                      {(finalReport.report.key_metrics || finalReport.report.keyMetrics || finalReport.report.metrics) && (
                        <ReportSection 
                          title="Key Metrics" 
                          data={finalReport.report.key_metrics || finalReport.report.keyMetrics || finalReport.report.metrics}
                          color="#4caf50"
                          icon={<TrendingUpIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Risk Assessment */}
                      {(finalReport.report.risk_assessment || finalReport.report.riskAssessment || finalReport.report.risk) && (
                        <ReportSection 
                          title="Risk Assessment" 
                          data={finalReport.report.risk_assessment || finalReport.report.riskAssessment || finalReport.report.risk}
                          color="#ff6b6b"
                          icon={<WarningIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Critical Findings Analysis */}
                      {(finalReport.report.critical_findings_analysis || finalReport.report.criticalFindings || finalReport.report.findings_analysis || finalReport.report.critical_vulnerabilities) && (
                        <ReportSection 
                          title="Critical Findings Analysis" 
                          data={finalReport.report.critical_findings_analysis || finalReport.report.criticalFindings || finalReport.report.findings_analysis || finalReport.report.critical_vulnerabilities}
                          color="#ff4444"
                          icon={<BugReportIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Vulnerability Summary */}
                      {(finalReport.report.vulnerability_summary || finalReport.report.vulnerabilitySummary || finalReport.report.vulnerabilities) && (
                        <ReportSection 
                          title="Vulnerability Summary" 
                          data={finalReport.report.vulnerability_summary || finalReport.report.vulnerabilitySummary || finalReport.report.vulnerabilities}
                          color="#ff9800"
                          icon={<GppMaybeIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Remediation Priorities */}
                      {(finalReport.report.remediation_priorities || finalReport.report.remediationPriorities || finalReport.report.remediation) && (
                        <ReportSection 
                          title="Remediation Priorities" 
                          data={finalReport.report.remediation_priorities || finalReport.report.remediationPriorities || finalReport.report.remediation}
                          color="#00ff88"
                          icon={<VerifiedUserIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Additional Recommendations */}
                      {(finalReport.report.additional_testing_recommendations || finalReport.report.additionalRecommendations || finalReport.report.recommendations) && (
                        <ReportSection 
                          title="Additional Testing Recommendations" 
                          data={finalReport.report.additional_testing_recommendations || finalReport.report.additionalRecommendations || finalReport.report.recommendations}
                          color="#ffaa00"
                          icon={<LightbulbIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Compliance Implications */}
                      {(finalReport.report.compliance_implications || finalReport.report.compliance) && (
                        <ReportSection 
                          title="Compliance Implications" 
                          data={finalReport.report.compliance_implications || finalReport.report.compliance}
                          color="#ff00ff"
                          icon={<AssignmentTurnedInIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* False Positive Assessment */}
                      {(finalReport.report.false_positive_assessment || finalReport.report.falsePositives) && (
                        <ReportSection 
                          title="False Positive Assessment" 
                          data={finalReport.report.false_positive_assessment || finalReport.report.falsePositives}
                          color="#888888"
                        />
                      )}
                      
                      {/* Conclusion */}
                      {(finalReport.report.conclusion || finalReport.report.final_assessment) && (
                        <ReportSection 
                          title="Conclusion" 
                          data={finalReport.report.conclusion || finalReport.report.final_assessment}
                          color="#9c27b0"
                          icon={<CheckCircleIcon sx={{ fontSize: 18 }} />}
                        />
                      )}
                      
                      {/* Fallback: Show all other keys not already displayed */}
                      {(() => {
                        const displayedKeys = [
                          'assessment_overview', 'assessmentOverview', 'overview',
                          'executive_summary', 'summary', 'executiveSummary',
                          'key_metrics', 'keyMetrics', 'metrics',
                          'risk_assessment', 'riskAssessment', 'risk',
                          'critical_findings_analysis', 'criticalFindings', 'findings_analysis', 'critical_vulnerabilities',
                          'vulnerability_summary', 'vulnerabilitySummary', 'vulnerabilities',
                          'remediation_priorities', 'remediationPriorities', 'remediation',
                          'additional_testing_recommendations', 'additionalRecommendations', 'recommendations',
                          'compliance_implications', 'compliance',
                          'false_positive_assessment', 'falsePositives',
                          'conclusion', 'final_assessment'
                        ];
                        const remainingKeys = Object.keys(finalReport.report).filter(k => !displayedKeys.includes(k));
                        if (remainingKeys.length > 0) {
                          return remainingKeys.map(key => (
                            <ReportSection 
                              key={key}
                              title={key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())} 
                              data={finalReport.report[key]}
                              color="#6b8e9f"
                            />
                          ));
                        }
                        return null;
                      })()}
                    </>
                  ) : (
                    /* Show session summary if no report object */
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#aaaaaa", mb: 1 }}>
                        Session Summary
                      </Typography>
                      {finalReport.session_summary && (
                        <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                          Targets: {finalReport.session_summary.targets?.length || 0} | 
                          Iterations: {finalReport.session_summary.iterations || 0} | 
                          Findings: {finalReport.session_summary.findings?.length || 0}
                        </Typography>
                      )}
                      {finalReport.error && (
                        <Typography variant="body2" color="error" sx={{ mt: 1 }}>
                          Error: {finalReport.error}
                        </Typography>
                      )}
                    </Box>
                  )}
                  
                  {/* Attack Chains from correlation */}
                  {finalReport.correlation_analysis?.attack_chains?.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#9c27b0", mb: 1 }}>
                        Discovered Attack Chains ({finalReport.correlation_analysis.attack_chains.length})
                      </Typography>
                      {finalReport.correlation_analysis.attack_chains.map((chain: any, i: number) => (
                        <Box key={i} sx={{ 
                          p: 1, 
                          mb: 1, 
                          bgcolor: "rgba(156, 39, 176, 0.1)", 
                          borderRadius: 1,
                          borderLeft: "3px solid #9c27b0",
                        }}>
                          <Typography variant="body2" fontWeight="bold">
                            {chain.name || `Chain ${i + 1}`}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            Steps: {chain.steps?.join(' → ') || 'N/A'}
                          </Typography>
                          <Typography variant="caption" display="block" color="error.main">
                            Impact: {chain.impact || 'Unknown'}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  )}
                </Box>
              )}
            </CardContent>
          </Card>
          
          {/* Error Alert */}
          {error && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
              {error}
            </Alert>
          )}
          
          {/* Fingerprint Card */}
          {fingerprint && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
              border: "1px solid rgba(138, 43, 226, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#8a2be2" }}>
                  <FingerprintIcon sx={{ color: "#8a2be2" }} />
                  Target Fingerprint
                </Typography>
                
                <Grid container spacing={2}>
                  {fingerprint.server && (
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Server</Typography>
                      <Typography variant="body2">{fingerprint.server}</Typography>
                    </Grid>
                  )}
                  {fingerprint.framework && (
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Framework</Typography>
                      <Typography variant="body2">{fingerprint.framework}</Typography>
                    </Grid>
                  )}
                  {fingerprint.language && (
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Language</Typography>
                      <Typography variant="body2">{fingerprint.language}</Typography>
                    </Grid>
                  )}
                  {fingerprint.waf !== "none" && (
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">WAF Detected</Typography>
                      <Chip 
                        icon={<ShieldIcon />}
                        label={fingerprint.waf}
                        color="warning"
                        size="small"
                      />
                    </Grid>
                  )}
                </Grid>
                
                {fingerprint.technologies.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="caption" color="text.secondary">Technologies</Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {fingerprint.technologies.map((tech, i) => (
                        <Chip key={i} label={tech} size="small" variant="outlined" />
                      ))}
                    </Box>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}
          
          {/* Discovered Endpoints Card */}
          {discoveredEndpoints.length > 0 && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(15, 26, 46, 0.8) 100%)",
              border: "1px solid rgba(0, 191, 255, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#00bfff" }}>
                  <ExploreIcon sx={{ color: "#00bfff" }} />
                  Discovered Endpoints ({discoveredEndpoints.length})
                  <Chip label={`${totalTargets} targets`} size="small" color="primary" sx={{ ml: "auto" }} />
                </Typography>
                
                <List dense>
                  {discoveredEndpoints.slice(0, 10).map((endpoint, i) => (
                    <ListItem key={i} sx={{ py: 0.5 }}>
                      <ListItemIcon sx={{ minWidth: 40 }}>
                        <Chip label={endpoint.method} size="small" color={endpoint.method === "POST" ? "warning" : "default"} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.85rem" }}>
                            {endpoint.url}
                          </Typography>
                        }
                        secondary={
                          endpoint.parameters.length > 0 ? (
                            <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                              {endpoint.parameters.map((p, j) => (
                                <Chip key={j} label={p} size="small" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ))}
                            </Box>
                          ) : (
                            <Typography variant="caption" color="text.secondary">
                              Source: {endpoint.source}
                            </Typography>
                          )
                        }
                      />
                    </ListItem>
                  ))}
                  {discoveredEndpoints.length > 10 && (
                    <Typography variant="caption" color="text.secondary" sx={{ pl: 2 }}>
                      +{discoveredEndpoints.length - 10} more endpoints
                    </Typography>
                  )}
                </List>
              </CardContent>
            </Card>
          )}
          
          {/* Attack Chains Card */}
          {attackChains.length > 0 && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(46, 10, 36, 0.8) 100%)",
              border: "1px solid rgba(156, 39, 176, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#9c27b0" }}>
                  <AccountTreeIcon sx={{ color: "#9c27b0" }} />
                  Attack Chains ({attackChains.length})
                </Typography>
                
                {attackChains.map((chain) => (
                  <Paper
                    key={chain.id}
                    sx={{
                      p: 2,
                      mb: 1,
                      borderLeft: 4,
                      borderColor: chain.status === "success" ? "success.main" : chain.status === "failed" ? "error.main" : "warning.main",
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                      <Typography variant="subtitle1" fontWeight="bold">
                        {chain.name}
                      </Typography>
                      <Chip
                        label={chain.status}
                        size="small"
                        color={chain.status === "success" ? "success" : chain.status === "failed" ? "error" : "warning"}
                      />
                      <Button
                        size="small"
                        onClick={() => setShowChainDetails(showChainDetails === chain.id ? null : chain.id)}
                      >
                        {showChainDetails === chain.id ? "Hide" : "Details"}
                      </Button>
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      {chain.description}
                    </Typography>
                    
                    {/* Progress steps */}
                    <Stepper activeStep={chain.current_step} alternativeLabel sx={{ mt: 2 }}>
                      {chain.steps.map((step, i) => (
                        <Step key={i} completed={step.success}>
                          <StepLabel
                            error={chain.status === "failed" && i === chain.current_step}
                            StepIconProps={{
                              sx: {
                                color: step.success ? "success.main" : undefined,
                              }
                            }}
                          >
                            {step.technique}
                          </StepLabel>
                        </Step>
                      ))}
                    </Stepper>
                    
                    <Collapse in={showChainDetails === chain.id}>
                      <Box sx={{ mt: 2 }}>
                        {chain.steps.map((step, i) => (
                          <Box
                            key={i}
                            sx={{
                              p: 1,
                              mb: 1,
                              bgcolor: alpha(step.success ? theme.palette.success.main : theme.palette.grey[500], 0.1),
                              borderRadius: 1,
                            }}
                          >
                            <Typography variant="caption" color="text.secondary">
                              Step {i + 1}: {step.technique}
                            </Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                              Payload: {step.payload}
                            </Typography>
                            <Typography variant="caption">
                              Expected: {step.expected_outcome} {step.success ? "✓" : step.actual_outcome ? "✗" : "..."}
                            </Typography>
                            {step.actual_outcome && (
                              <Typography variant="caption" display="block" color="text.secondary">
                                Actual: {step.actual_outcome.slice(0, 100)}...
                              </Typography>
                            )}
                          </Box>
                        ))}
                      </Box>
                    </Collapse>
                    
                    {chain.final_impact && (
                      <Alert severity="error" sx={{ mt: 2 }}>
                        <Typography variant="body2" fontWeight="bold">
                          Impact: {chain.final_impact}
                        </Typography>
                      </Alert>
                    )}
                  </Paper>
                ))}
              </CardContent>
            </Card>
          )}
          
          {/* Blind Detection Results Card */}
          {blindResults.length > 0 && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
              border: "1px solid rgba(255, 165, 0, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#ffa500" }}>
                  <TimerIcon sx={{ color: "#ffa500" }} />
                  Blind Detection Results ({blindResults.filter(r => r.detected).length}/{blindResults.length})
                </Typography>
                
                <List dense>
                  {blindResults.map((result, i) => (
                    <ListItem key={i}>
                      <ListItemIcon>
                        {result.detected ? (
                          <CheckCircleIcon color="success" />
                        ) : (
                          <ErrorIcon color="disabled" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Typography variant="body2">
                              {result.technique} ({result.detection_method})
                            </Typography>
                            {result.detected && (
                              <Chip label="VULNERABLE" size="small" color="error" />
                            )}
                          </Box>
                        }
                        secondary={
                          <Typography variant="caption">
                            Baseline: {result.baseline_time.toFixed(0)}ms → 
                            Payload: {result.payload_time.toFixed(0)}ms 
                            (Δ{result.time_difference.toFixed(0)}ms) 
                            | Confidence: {(result.confidence * 100).toFixed(0)}%
                          </Typography>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}
          
          {/* Findings Card */}
          {findings.length > 0 && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(46, 10, 26, 0.8) 100%)",
              border: "1px solid rgba(255, 0, 100, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#ff0066" }}>
                  <BugReportIcon sx={{ color: "#ff0066" }} />
                  Findings ({findings.length})
                </Typography>
                
                <List>
                  {findings.map((finding, index) => (
                    <Paper
                      key={finding.id || index}
                      sx={{
                        p: 2,
                        mb: 1,
                        borderLeft: 4,
                        borderColor: getSeverityColor(finding.severity),
                        background: "rgba(10, 10, 15, 0.8)",
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
                        <Chip
                          label={finding.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getSeverityColor(finding.severity), 0.2),
                            color: getSeverityColor(finding.severity),
                            fontWeight: "bold",
                          }}
                        />
                        <Chip
                          label={finding.technique}
                          size="small"
                          variant="outlined"
                        />
                        {finding.cvss_score !== undefined && finding.cvss_score > 0 && (
                          <Chip
                            label={`CVSS: ${finding.cvss_score.toFixed(1)}`}
                            size="small"
                            color={finding.cvss_score >= 9 ? "error" : finding.cvss_score >= 7 ? "warning" : "info"}
                          />
                        )}
                        {finding.cwe_id && (
                          <Chip
                            label={finding.cwe_id}
                            size="small"
                            variant="outlined"
                            color="secondary"
                          />
                        )}
                      </Box>
                      
                      <Typography variant="subtitle1" fontWeight="bold">
                        {finding.title}
                      </Typography>
                      
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {finding.description}
                      </Typography>
                      
                      {finding.recommendation && (
                        <Alert severity="info" sx={{ mt: 1, py: 0 }}>
                          <Typography variant="caption">{finding.recommendation}</Typography>
                        </Alert>
                      )}
                      
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" color="text.secondary">
                          Endpoint: {finding.endpoint}
                        </Typography>
                        {finding.parameter && (
                          <Typography variant="caption" color="text.secondary" sx={{ ml: 2 }}>
                            Parameter: {finding.parameter}
                          </Typography>
                        )}
                      </Box>
                      
                      <Box sx={{ mt: 1, p: 1, bgcolor: alpha(theme.palette.background.default, 0.5), borderRadius: 1 }}>
                        <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                          Payload: {finding.payload}
                        </Typography>
                        <Tooltip title="Copy payload">
                          <IconButton
                            size="small"
                            onClick={() => navigator.clipboard.writeText(finding.payload)}
                          >
                            <ContentCopyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                      
                      {finding.proof_of_concept && (
                        <Box sx={{ mt: 1 }}>
                          <Button
                            size="small"
                            startIcon={<CodeIcon />}
                            onClick={() => setShowPoc(showPoc === finding.id ? null : finding.id)}
                          >
                            {showPoc === finding.id ? "Hide PoC" : "View Proof of Concept"}
                          </Button>
                          <Collapse in={showPoc === finding.id}>
                            <Box
                              sx={{
                                mt: 1,
                                p: 1,
                                bgcolor: alpha(theme.palette.common.black, 0.9),
                                color: theme.palette.success.light,
                                borderRadius: 1,
                                fontFamily: "monospace",
                                fontSize: "0.75rem",
                                maxHeight: 200,
                                overflow: "auto",
                                whiteSpace: "pre-wrap",
                              }}
                            >
                              {finding.proof_of_concept}
                            </Box>
                            <Button
                              size="small"
                              onClick={() => navigator.clipboard.writeText(finding.proof_of_concept!)}
                              sx={{ mt: 0.5 }}
                            >
                              Copy PoC
                            </Button>
                          </Collapse>
                        </Box>
                      )}
                    </Paper>
                  ))}
                </List>
              </CardContent>
            </Card>
          )}
          
          {/* LLM Analysis Card */}
          {llmAnalysis.length > 0 && (
            <Card sx={{ 
              mb: 2,
              background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
              border: "1px solid rgba(0, 255, 255, 0.3)",
            }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#00ffff" }}>
                  <PsychologyIcon sx={{ color: "#00ffff" }} />
                  AI Analysis
                </Typography>
                
                <Box
                  sx={{
                    maxHeight: 300,
                    overflow: "auto",
                    p: 2,
                    bgcolor: "rgba(0, 255, 255, 0.05)",
                    border: "1px solid rgba(0, 255, 255, 0.2)",
                    borderRadius: 1,
                  }}
                >
                  {llmAnalysis.map((analysis, index) => (
                    <Box key={index} sx={{ mb: 2 }}>
                      <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                        {analysis}
                      </Typography>
                      {index < llmAnalysis.length - 1 && <Divider sx={{ my: 1 }} />}
                    </Box>
                  ))}
                </Box>
              </CardContent>
            </Card>
          )}
          
          {/* Live Updates Card */}
          <Card sx={{
            background: "linear-gradient(135deg, rgba(10, 10, 15, 0.95) 0%, rgba(26, 10, 46, 0.8) 100%)",
            border: "1px solid rgba(255, 0, 255, 0.3)",
            backdropFilter: "blur(10px)",
          }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1, fontFamily: "'Orbitron', monospace", color: "#ff00ff" }}>
                <TimelineIcon sx={{ color: "#ff00ff" }} />
                Live Updates
              </Typography>
              
              <Box
                sx={{
                  maxHeight: 400,
                  overflow: "auto",
                  p: 2,
                  bgcolor: "rgba(10, 10, 15, 0.8)",
                  border: "1px solid rgba(0, 255, 255, 0.2)",
                  borderRadius: 1,
                  fontFamily: "monospace",
                  fontSize: "0.85rem",
                }}
              >
                {updates.length === 0 ? (
                  <Typography color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
                    Start a scan to see live updates
                  </Typography>
                ) : (
                  updates.map((update, index) => (
                    <Box
                      key={index}
                      sx={{
                        py: 0.5,
                        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
                        "&:last-child": { borderBottom: "none" },
                      }}
                    >
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {update.type === "error" ? (
                          <ErrorIcon fontSize="small" color="error" />
                        ) : update.type === "finding" ? (
                          <BugReportIcon fontSize="small" color="warning" />
                        ) : update.type === "complete" ? (
                          <CheckCircleIcon fontSize="small" color="success" />
                        ) : (
                          <InfoIcon fontSize="small" color="info" />
                        )}
                        <Typography
                          variant="body2"
                          color={
                            update.type === "error" ? "error" :
                            update.type === "finding" ? "warning.main" :
                            update.type === "complete" ? "success.main" :
                            "text.secondary"
                          }
                        >
                          {update.message || update.type}
                        </Typography>
                      </Box>
                      {update.reasoning && (
                        <Typography variant="caption" color="text.secondary" sx={{ pl: 3, display: "block" }}>
                          {update.reasoning}
                        </Typography>
                      )}
                    </Box>
                  ))
                )}
                <div ref={updatesEndRef} />
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
};

export default AgenticFuzzerPage;
