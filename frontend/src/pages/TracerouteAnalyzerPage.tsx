import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "../components/ChatCodeBlock";
import {
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Alert,
  CircularProgress,
  Chip,
  IconButton,
  Tooltip,
  Slider,
  FormControlLabel,
  Switch,
  Card,
  CardContent,
  Collapse,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Snackbar,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Grid,
  Divider,
  LinearProgress,
  alpha,
  useTheme,
} from "@mui/material";
import {
  Route as RouteIcon,
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Refresh as RefreshIcon,
  ArrowBack as BackIcon,
  NetworkCheck as NetworkIcon,
  Speed as SpeedIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Info as InfoIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Chat as ChatIcon,
  Close as CloseIcon,
  Send as SendIcon,
  History as HistoryIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  Timeline as TimelineIcon,
  TrendingUp as TrendingIcon,
  FiberManualRecord as DotIcon,
  Download as DownloadIcon,
  MenuBook as LearnIcon,
  Public as PublicIcon,
  Hub as HubIcon,
  OpenInFull as OpenInFullIcon,
  CloseFullscreen as CloseFullscreenIcon,
  SmartToy as SmartToyIcon,
  Person as PersonIcon,
  Radar as RadarIcon,
  Upload as UploadIcon,
  Terminal as TerminalIcon,
  AccountTree as TopologyIcon,
  BugReport as FindingsIcon,
} from "@mui/icons-material";
import NmapNetworkGraph from "../components/NmapNetworkGraph";
import NmapFindingsTab from "../components/NmapFindingsTab";
import HostDetailsDrawer from "../components/HostDetailsDrawer";
import NmapExportOptions from "../components/NmapExportOptions";
import { Link } from "react-router-dom";
import {
  apiClient,
  TracerouteStatus,
  TracerouteRequest,
  TracerouteResponse,
  TracerouteHop,
  TracerouteAIAnalysis,
  TracerouteSavedReport,
  TracerouteReportDetail,
  BatchTracerouteRequest,
  BatchTracerouteResponse,
  BatchTracerouteResult,
  BatchTracerouteCombinedTopology,
  BatchTracerouteComparativeAnalysis,
  NmapAnalysisResult,
  NmapScanType,
  SavedNetworkReport,
} from "../api/client";
import NetworkTopologyGraph, { TopologyNode, TopologyLink } from "../components/NetworkTopologyGraph";

// Tool mode type
type ToolMode = "traceroute" | "nmap-scan" | "nmap-analyze" | "nmap-command";

// ============================================================================
// Network Path Visualization Component
// ============================================================================

interface PathVisualizationProps {
  hops: TracerouteHop[];
  target: string;
  completed: boolean;
}

const PathVisualization: React.FC<PathVisualizationProps> = ({ hops, target, completed }) => {
  const getHopColor = (hop: TracerouteHop) => {
    if (hop.is_timeout) return "#6b7280"; // Gray
    if (hop.packet_loss > 50) return "#ef4444"; // Red
    if (hop.packet_loss > 20) return "#f59e0b"; // Yellow
    if (hop.avg_rtt_ms && hop.avg_rtt_ms > 200) return "#f59e0b"; // High latency
    if (hop.is_destination) return "#10b981"; // Green for destination
    return "#3b82f6"; // Blue for normal
  };

  const getLatencyBarWidth = (hop: TracerouteHop) => {
    if (!hop.avg_rtt_ms) return 0;
    const maxLatency = Math.max(...hops.map(h => h.avg_rtt_ms || 0), 1);
    return (hop.avg_rtt_ms / maxLatency) * 100;
  };

  return (
    <Box sx={{ py: 2 }}>
      {/* Start node */}
      <Box sx={{ display: "flex", alignItems: "center", mb: 1 }}>
        <Box
          sx={{
            width: 40,
            height: 40,
            borderRadius: "50%",
            bgcolor: "#3b82f6",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            color: "white",
            fontWeight: "bold",
            mr: 2,
          }}
        >
          S
        </Box>
        <Typography variant="body1" sx={{ fontWeight: "bold" }}>
          Your Machine
        </Typography>
      </Box>

      {/* Hops */}
      {hops.map((hop, index) => (
        <Box key={hop.hop_number}>
          {/* Connection line */}
          <Box
            sx={{
              width: 2,
              height: 30,
              bgcolor: getHopColor(hop),
              ml: "19px",
              opacity: 0.5,
            }}
          />
          
          {/* Hop node */}
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            {/* Hop number circle */}
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: "50%",
                bgcolor: getHopColor(hop),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "white",
                fontWeight: "bold",
                fontSize: "0.875rem",
              }}
            >
              {hop.hop_number}
            </Box>

            {/* Hop info */}
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                {hop.is_timeout ? (
                  <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
                    * * * (Request timeout)
                  </Typography>
                ) : (
                  <>
                    <Typography variant="body1" sx={{ fontFamily: "monospace", fontWeight: "medium" }}>
                      {hop.ip_address || "Unknown"}
                    </Typography>
                    {hop.hostname && hop.hostname !== hop.ip_address && (
                      <Typography variant="body2" color="text.secondary">
                        ({hop.hostname})
                      </Typography>
                    )}
                  </>
                )}
                {hop.is_destination && (
                  <Chip label="Destination" size="small" color="success" sx={{ ml: 1 }} />
                )}
                {hop.packet_loss > 0 && !hop.is_timeout && (
                  <Chip
                    label={`${hop.packet_loss.toFixed(0)}% loss`}
                    size="small"
                    color="error"
                    sx={{ ml: 1 }}
                  />
                )}
              </Box>

              {/* RTT values */}
              {!hop.is_timeout && hop.rtt_ms.length > 0 && (
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mt: 0.5 }}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    {hop.rtt_ms.map((rtt, i) => (
                      <Typography key={i} variant="caption" color="text.secondary">
                        {rtt < 1 ? "<1" : rtt.toFixed(1)}ms
                      </Typography>
                    ))}
                  </Box>
                  {hop.avg_rtt_ms && (
                    <Typography variant="caption" color="primary">
                      (avg: {hop.avg_rtt_ms.toFixed(1)}ms)
                    </Typography>
                  )}
                </Box>
              )}

              {/* Latency bar */}
              {!hop.is_timeout && hop.avg_rtt_ms && (
                <Box sx={{ mt: 1, width: "100%", maxWidth: 300 }}>
                  <LinearProgress
                    variant="determinate"
                    value={getLatencyBarWidth(hop)}
                    sx={{
                      height: 4,
                      borderRadius: 2,
                      bgcolor: "rgba(0,0,0,0.1)",
                      "& .MuiLinearProgress-bar": {
                        bgcolor: getHopColor(hop),
                      },
                    }}
                  />
                </Box>
              )}
            </Box>
          </Box>
        </Box>
      ))}

      {/* Final connection if not completed */}
      {!completed && hops.length > 0 && (
        <>
          <Box
            sx={{
              width: 2,
              height: 30,
              bgcolor: "#6b7280",
              ml: "19px",
              opacity: 0.3,
              backgroundImage: "repeating-linear-gradient(to bottom, currentColor 0, currentColor 4px, transparent 4px, transparent 8px)",
            }}
          />
          <Box sx={{ display: "flex", alignItems: "center" }}>
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: "50%",
                border: "2px dashed #6b7280",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                color: "#6b7280",
                mr: 2,
              }}
            >
              ?
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
              {target} (not reached)
            </Typography>
          </Box>
        </>
      )}
    </Box>
  );
};

// ============================================================================
// Latency Chart Component
// ============================================================================

interface LatencyChartProps {
  hops: TracerouteHop[];
}

const LatencyChart: React.FC<LatencyChartProps> = ({ hops }) => {
  const maxLatency = Math.max(...hops.map(h => h.avg_rtt_ms || 0), 1);
  const chartHeight = 200;

  const validHops = hops.filter(h => !h.is_timeout && h.avg_rtt_ms);

  if (validHops.length === 0) {
    return (
      <Box sx={{ p: 3, textAlign: "center" }}>
        <Typography color="text.secondary">No latency data available</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 2 }}>
      <Typography variant="subtitle2" gutterBottom>
        Latency by Hop (ms)
      </Typography>
      <Box
        sx={{
          display: "flex",
          alignItems: "flex-end",
          gap: 0.5,
          height: chartHeight,
          p: 2,
          bgcolor: "rgba(0,0,0,0.02)",
          borderRadius: 1,
        }}
      >
        {hops.map((hop, index) => {
          const height = hop.is_timeout || !hop.avg_rtt_ms 
            ? 0 
            : (hop.avg_rtt_ms / maxLatency) * (chartHeight - 40);
          
          const color = hop.is_timeout ? "#6b7280" :
            hop.avg_rtt_ms! > 200 ? "#ef4444" :
            hop.avg_rtt_ms! > 100 ? "#f59e0b" :
            "#3b82f6";

          return (
            <Tooltip
              key={hop.hop_number}
              title={
                hop.is_timeout 
                  ? `Hop ${hop.hop_number}: Timeout` 
                  : `Hop ${hop.hop_number}: ${hop.avg_rtt_ms?.toFixed(1)}ms${hop.ip_address ? ` (${hop.ip_address})` : ""}`
              }
            >
              <Box
                sx={{
                  flex: 1,
                  minWidth: 20,
                  maxWidth: 50,
                  display: "flex",
                  flexDirection: "column",
                  alignItems: "center",
                }}
              >
                <Box
                  sx={{
                    width: "100%",
                    height: Math.max(height, hop.is_timeout ? 5 : 0),
                    bgcolor: color,
                    borderRadius: "4px 4px 0 0",
                    transition: "height 0.3s ease",
                    cursor: "pointer",
                    "&:hover": {
                      opacity: 0.8,
                    },
                  }}
                />
                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                  {hop.hop_number}
                </Typography>
              </Box>
            </Tooltip>
          );
        })}
      </Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}>
        <Typography variant="caption" color="text.secondary">
          0ms
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {maxLatency.toFixed(0)}ms
        </Typography>
      </Box>
    </Box>
  );
};

// ============================================================================
// AI Analysis Panel
// ============================================================================

interface AIAnalysisPanelProps {
  analysis: TracerouteAIAnalysis;
}

// Helper to safely render any value as string (handles objects that would crash React)
const safeText = (value: any): string => {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return "[Object]";
    }
  }
  return String(value);
};

const AIAnalysisPanel: React.FC<AIAnalysisPanelProps> = ({ analysis }) => {
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    summary: true,
    segments: true,
    performance: true,
    security: true,
    recommendations: true,
  });

  const toggleSection = (section: string) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  // Handle null/undefined analysis
  if (!analysis) {
    return (
      <Alert severity="info" sx={{ mb: 2 }}>
        AI analysis is not available for this traceroute. Try running a new traceroute to generate AI analysis.
      </Alert>
    );
  }

  if (analysis.error) {
    return (
      <Alert severity="warning" sx={{ mb: 2 }}>
        AI analysis unavailable: {analysis.error}
      </Alert>
    );
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "high":
      case "critical":
        return "error";
      case "medium":
        return "warning";
      case "low":
        return "info";
      default:
        return "default";
    }
  };

  return (
    <Box>
      {/* Summary */}
      {analysis.summary && (
        <Card sx={{ mb: 2 }}>
          <CardContent
            sx={{ cursor: "pointer", pb: 1 }}
            onClick={() => toggleSection("summary")}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Typography variant="h6">Summary</Typography>
              {expandedSections.summary ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </Box>
          </CardContent>
          <Collapse in={expandedSections.summary}>
            <CardContent sx={{ pt: 0 }}>
              <Typography variant="body2">{safeText(analysis.summary)}</Typography>
              {analysis.risk_score !== undefined && (
                <Box sx={{ mt: 2, display: "flex", alignItems: "center", gap: 2 }}>
                  <Typography variant="body2" fontWeight="bold">Risk Score:</Typography>
                  <Chip
                    label={`${analysis.risk_score}/100`}
                    color={analysis.risk_score >= 70 ? "error" : analysis.risk_score >= 40 ? "warning" : "success"}
                  />
                </Box>
              )}
            </CardContent>
          </Collapse>
        </Card>
      )}

      {/* Network Segments */}
      {analysis.network_segments && analysis.network_segments.length > 0 && (
        <Card sx={{ mb: 2 }}>
          <CardContent
            sx={{ cursor: "pointer", pb: 1 }}
            onClick={() => toggleSection("segments")}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Typography variant="h6">Network Segments</Typography>
              {expandedSections.segments ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </Box>
          </CardContent>
          <Collapse in={expandedSections.segments}>
            <CardContent sx={{ pt: 0 }}>
              <List dense>
                {analysis.network_segments.map((segment, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <RouteIcon color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={`${safeText(segment.segment)} (Hops ${safeText(segment.hops)})`}
                      secondary={safeText(segment.description)}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Collapse>
        </Card>
      )}

      {/* Performance Analysis */}
      {analysis.performance_analysis && (
        <Card sx={{ mb: 2 }}>
          <CardContent
            sx={{ cursor: "pointer", pb: 1 }}
            onClick={() => toggleSection("performance")}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Typography variant="h6">Performance Analysis</Typography>
              {expandedSections.performance ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </Box>
          </CardContent>
          <Collapse in={expandedSections.performance}>
            <CardContent sx={{ pt: 0 }}>
              <Typography variant="body2" paragraph>
                <strong>Overall Latency:</strong> {safeText(analysis.performance_analysis.overall_latency)}
              </Typography>
              
              {analysis.performance_analysis.bottlenecks && analysis.performance_analysis.bottlenecks.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="error.main" gutterBottom>
                    Bottlenecks Identified:
                  </Typography>
                  <List dense>
                    {analysis.performance_analysis.bottlenecks.map((bottleneck, i) => (
                      <ListItem key={i}>
                        <ListItemIcon>
                          <WarningIcon color="error" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={safeText(bottleneck)} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}

              {analysis.performance_analysis.packet_loss_concerns && analysis.performance_analysis.packet_loss_concerns.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" color="warning.main" gutterBottom>
                    Packet Loss Concerns:
                  </Typography>
                  <List dense>
                    {analysis.performance_analysis.packet_loss_concerns.map((concern, i) => (
                      <ListItem key={i}>
                        <ListItemIcon>
                          <ErrorIcon color="warning" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={safeText(concern)} />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}
            </CardContent>
          </Collapse>
        </Card>
      )}

      {/* Security Observations */}
      {analysis.security_observations && analysis.security_observations.length > 0 && (
        <Card sx={{ mb: 2 }}>
          <CardContent
            sx={{ cursor: "pointer", pb: 1 }}
            onClick={() => toggleSection("security")}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Typography variant="h6">Security Observations</Typography>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <Chip 
                  label={analysis.security_observations.length} 
                  size="small" 
                  color="warning" 
                />
                {expandedSections.security ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              </Box>
            </Box>
          </CardContent>
          <Collapse in={expandedSections.security}>
            <CardContent sx={{ pt: 0 }}>
              {analysis.security_observations.map((obs, index) => (
                <Paper key={index} sx={{ p: 2, mb: 1, bgcolor: "rgba(0,0,0,0.02)" }} elevation={0}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <SecurityIcon fontSize="small" color="action" />
                    <Typography variant="subtitle2">{safeText(obs.observation)}</Typography>
                    <Chip
                      label={safeText(obs.severity)}
                      size="small"
                      color={getSeverityColor(safeText(obs.severity)) as any}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {safeText(obs.details)}
                  </Typography>
                </Paper>
              ))}
            </CardContent>
          </Collapse>
        </Card>
      )}

      {/* Recommendations */}
      {analysis.recommendations && analysis.recommendations.length > 0 && (
        <Card sx={{ mb: 2 }}>
          <CardContent
            sx={{ cursor: "pointer", pb: 1 }}
            onClick={() => toggleSection("recommendations")}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <Typography variant="h6">Recommendations</Typography>
              {expandedSections.recommendations ? <ExpandLessIcon /> : <ExpandMoreIcon />}
            </Box>
          </CardContent>
          <Collapse in={expandedSections.recommendations}>
            <CardContent sx={{ pt: 0 }}>
              <List dense>
                {analysis.recommendations.map((rec, index) => (
                  <ListItem key={index}>
                    <ListItemIcon>
                      <CheckIcon color="success" />
                    </ListItemIcon>
                    <ListItemText primary={safeText(rec)} />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </Collapse>
        </Card>
      )}

      {/* Raw analysis fallback */}
      {analysis.raw_analysis && !analysis.summary && (
        <Card>
          <CardContent>
            <Typography variant="h6" gutterBottom>Analysis</Typography>
            <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
              {safeText(analysis.raw_analysis)}
            </Typography>
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

// ============================================================================
// Main TracerouteAnalyzerPage Component
// ============================================================================

const TracerouteAnalyzerPage: React.FC = () => {
  const navigate = useNavigate();

  // Tool mode selector
  const [toolMode, setToolMode] = useState<ToolMode>("traceroute");

  // Status and configuration
  const [status, setStatus] = useState<TracerouteStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Scan configuration
  const [target, setTarget] = useState("");
  const [maxHops, setMaxHops] = useState(30);
  const [timeout, setTimeout] = useState(5);
  const [queries, setQueries] = useState(3);
  const [useIcmp, setUseIcmp] = useState(true);
  const [resolveHostnames, setResolveHostnames] = useState(true);
  const [saveReport, setSaveReport] = useState(true);
  const [reportTitle, setReportTitle] = useState("");

  // Scan state
  const [scanning, setScanning] = useState(false);
  const [liveHops, setLiveHops] = useState<Array<{ number: number; raw: string }>>([]);
  const [result, setResult] = useState<TracerouteResponse | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  // UI state
  const [activeTab, setActiveTab] = useState(0);
  const [showChat, setShowChat] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: "success" | "error" | "info" }>({
    open: false,
    message: "",
    severity: "info",
  });

  // Chat state
  const [chatMessages, setChatMessages] = useState<Array<{ role: string; content: string }>>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const theme = useTheme();

  // Auto-scroll chat to bottom
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Saved reports
  const [savedReports, setSavedReports] = useState<TracerouteSavedReport[]>([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [selectedReport, setSelectedReport] = useState<TracerouteReportDetail | null>(null);

  // Batch traceroute state
  const [batchMode, setBatchMode] = useState(false);
  const [batchTargets, setBatchTargets] = useState("");
  const [batchResult, setBatchResult] = useState<BatchTracerouteResponse | null>(null);
  const [batchScanning, setBatchScanning] = useState(false);

  // =====================================================
  // NMAP STATE
  // =====================================================
  const [nmapInstalled, setNmapInstalled] = useState(false);
  const [nmapScanTypes, setNmapScanTypes] = useState<NmapScanType[]>([]);
  const [nmapTarget, setNmapTarget] = useState("");
  const [nmapSelectedScanType, setNmapSelectedScanType] = useState("basic");
  const [nmapCustomPorts, setNmapCustomPorts] = useState("");
  const [nmapScanTitle, setNmapScanTitle] = useState("");
  const [nmapScanning, setNmapScanning] = useState(false);
  const [nmapResult, setNmapResult] = useState<NmapAnalysisResult | null>(null);
  const [nmapFiles, setNmapFiles] = useState<File[]>([]);
  const [nmapAnalyzing, setNmapAnalyzing] = useState(false);
  const [nmapSavedReports, setNmapSavedReports] = useState<SavedNetworkReport[]>([]);
  const [nmapActiveTab, setNmapActiveTab] = useState(0);
  const nmapFileInputRef = useRef<HTMLInputElement>(null);
  
  // Host details drawer state
  const [hostDrawerOpen, setHostDrawerOpen] = useState(false);
  const [selectedHost, setSelectedHost] = useState<any>(null);
  
  // NSE script options
  const [nseScriptCategories, setNseScriptCategories] = useState<{ id: string; name: string; description: string; examples: string[]; warning?: string }[]>([]);
  const [nseScripts, setNseScripts] = useState<{ id: string; name: string; description: string; category: string }[]>([]);
  const [selectedScriptCategories, setSelectedScriptCategories] = useState<string[]>([]);
  const [selectedScripts, setSelectedScripts] = useState<string[]>([]);
  const [showScriptOptions, setShowScriptOptions] = useState(false);

  // Command generator state
  const [cmdGenTarget, setCmdGenTarget] = useState("");
  const [cmdGenScanType, setCmdGenScanType] = useState("standard");
  const [cmdGenPorts, setCmdGenPorts] = useState("");
  const [cmdGenOutputFormat, setCmdGenOutputFormat] = useState<"xml" | "normal" | "grepable" | "all">("xml");
  const [cmdGenOutputFile, setCmdGenOutputFile] = useState("");
  const [cmdGenExtraFlags, setCmdGenExtraFlags] = useState("");

  // Nmap scan type options
  const nmapScanTypeOptions = useMemo(() => [
    { id: "ping", name: "Ping Sweep (Host Discovery)", flags: "-sn", description: "Find live hosts without port scan" },
    { id: "basic", name: "Basic Scan", flags: "", description: "Default top 1000 TCP ports" },
    { id: "quick", name: "Quick Scan", flags: "-T4 -F", description: "Fast scan of top 100 ports" },
    { id: "version", name: "Service Version Detection", flags: "-sV", description: "Detect service versions" },
    { id: "default-scripts", name: "Default Scripts", flags: "-sC", description: "Run default NSE scripts" },
    { id: "standard", name: "Standard (Version + Scripts)", flags: "-sV -sC", description: "Recommended for most scans" },
    { id: "aggressive", name: "Aggressive Scan", flags: "-A", description: "OS + Version + Scripts + Traceroute" },
    { id: "full", name: "Full Port Scan", flags: "-p-", description: "Scan all 65535 ports (slow)" },
    { id: "vuln", name: "Vulnerability Scan", flags: "--script vuln", description: "Run vulnerability detection scripts" },
    { id: "comprehensive", name: "Comprehensive", flags: "-sV -sC -O --script vuln", description: "Full security assessment" },
  ], []);

  // Initialize
  useEffect(() => {
    loadStatus();
    loadSavedReports();
    loadNmapStatus();
    loadNmapReports();
  }, []);

  const loadStatus = async () => {
    try {
      const s = await apiClient.getTracerouteStatus();
      setStatus(s);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to check traceroute status");
    } finally {
      setLoading(false);
    }
  };

  const loadSavedReports = async () => {
    setLoadingReports(true);
    try {
      const reports = await apiClient.getTracerouteReports();
      setSavedReports(reports);
    } catch (err) {
      console.error("Failed to load reports:", err);
    } finally {
      setLoadingReports(false);
    }
  };

  // =====================================================
  // NMAP FUNCTIONS
  // =====================================================
  const loadNmapStatus = async () => {
    try {
      const status = await apiClient.getNetworkStatus();
      setNmapInstalled(status.nmap_installed);
      // Also load scan types separately
      const scanTypes = await apiClient.getNmapScanTypes();
      setNmapScanTypes(scanTypes);
      // Load NSE script categories and scripts
      try {
        const categories = await apiClient.getNseScriptCategories();
        setNseScriptCategories(categories);
        const scripts = await apiClient.getNseScripts();
        setNseScripts(scripts);
      } catch (err) {
        console.error("Failed to load NSE scripts:", err);
      }
    } catch (err) {
      console.error("Failed to load Nmap status:", err);
    }
  };

  // Helper to extract summary statistics from NmapAnalysisResult
  const getNmapSummary = (result: NmapAnalysisResult) => {
    if (!result.analyses || result.analyses.length === 0) return null;
    const analysis = result.analyses[0];
    return {
      summary: analysis.summary,
      hosts: analysis.hosts || [],
      ai_analysis: analysis.ai_analysis,
      findings: analysis.findings || [],
    };
  };

  const loadNmapReports = async () => {
    try {
      const reports = await apiClient.getNetworkReports("nmap");
      setNmapSavedReports(reports);
    } catch (err) {
      console.error("Failed to load Nmap reports:", err);
    }
  };

  const handleNmapFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const droppedFiles = Array.from(e.dataTransfer.files).filter(
      f => f.name.endsWith('.xml') || f.name.endsWith('.nmap') || f.name.endsWith('.gnmap')
    );
    setNmapFiles(droppedFiles);
  };

  const handleNmapFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selectedFiles = Array.from(e.target.files).filter(
        f => f.name.endsWith('.xml') || f.name.endsWith('.nmap') || f.name.endsWith('.gnmap')
      );
      setNmapFiles(selectedFiles);
    }
  };

  const handleAnalyzeNmapFile = async () => {
    if (nmapFiles.length === 0) {
      setSnackbar({ open: true, message: "Please select an Nmap output file", severity: "error" });
      return;
    }

    setNmapAnalyzing(true);
    setError(null);
    setNmapResult(null);

    try {
      const result = await apiClient.analyzeNmap(nmapFiles, true, true, nmapScanTitle || undefined);
      setNmapResult(result);
      setSnackbar({ open: true, message: "Nmap analysis complete!", severity: "success" });
      loadNmapReports();
    } catch (err: any) {
      setError(err.message || "Failed to analyze Nmap file");
    } finally {
      setNmapAnalyzing(false);
    }
  };

  const handleRunNmapScan = async () => {
    if (!nmapTarget.trim()) {
      setSnackbar({ open: true, message: "Please enter a target", severity: "error" });
      return;
    }

    setNmapScanning(true);
    setError(null);
    setNmapResult(null);

    try {
      const result = await apiClient.runNmapScan({
        target: nmapTarget.trim(),
        scan_type: nmapSelectedScanType,
        ports: nmapCustomPorts || undefined,
        title: nmapScanTitle || undefined,
        scripts: selectedScripts.length > 0 ? selectedScripts : undefined,
        script_categories: selectedScriptCategories.length > 0 ? selectedScriptCategories : undefined,
      });
      setNmapResult(result);
      setSnackbar({ open: true, message: "Nmap scan complete!", severity: "success" });
      loadNmapReports();
    } catch (err: any) {
      setError(err.message || "Failed to run Nmap scan");
    } finally {
      setNmapScanning(false);
    }
  };

  // Generate nmap command based on selected options
  const generateNmapCommand = useCallback(() => {
    const selectedScan = nmapScanTypeOptions.find(s => s.id === cmdGenScanType);
    const parts = ["nmap"];
    
    // Add scan type flags
    if (selectedScan?.flags) {
      parts.push(selectedScan.flags);
    }
    
    // Add custom ports
    if (cmdGenPorts.trim()) {
      parts.push(`-p ${cmdGenPorts.trim()}`);
    }
    
    // Add output format
    if (cmdGenOutputFile.trim()) {
      switch (cmdGenOutputFormat) {
        case "xml":
          parts.push(`-oX ${cmdGenOutputFile.trim()}.xml`);
          break;
        case "normal":
          parts.push(`-oN ${cmdGenOutputFile.trim()}.nmap`);
          break;
        case "grepable":
          parts.push(`-oG ${cmdGenOutputFile.trim()}.gnmap`);
          break;
        case "all":
          parts.push(`-oA ${cmdGenOutputFile.trim()}`);
          break;
      }
    }
    
    // Add extra flags
    if (cmdGenExtraFlags.trim()) {
      parts.push(cmdGenExtraFlags.trim());
    }
    
    // Add target
    if (cmdGenTarget.trim()) {
      parts.push(cmdGenTarget.trim());
    } else {
      parts.push("<target>");
    }
    
    return parts.join(" ");
  }, [cmdGenScanType, cmdGenTarget, cmdGenPorts, cmdGenOutputFormat, cmdGenOutputFile, cmdGenExtraFlags, nmapScanTypeOptions]);

  const handleCopyCommand = () => {
    navigator.clipboard.writeText(generateNmapCommand());
    setSnackbar({ open: true, message: "Command copied to clipboard!", severity: "success" });
  };

  const handleRunTraceroute = async () => {
    if (!target.trim()) {
      setSnackbar({ open: true, message: "Please enter a target", severity: "error" });
      return;
    }

    setScanning(true);
    setLiveHops([]);
    setResult(null);
    setError(null);

    const request: TracerouteRequest = {
      target: target.trim(),
      max_hops: maxHops,
      timeout,
      queries,
      use_icmp: useIcmp,
      resolve_hostnames: resolveHostnames,
      save_report: saveReport,
      report_title: reportTitle || undefined,
    };

    abortControllerRef.current = apiClient.runTracerouteStream(
      request,
      (hopNumber, raw) => {
        setLiveHops(prev => [...prev, { number: hopNumber, raw }]);
      },
      (response) => {
        setResult(response);
        setScanning(false);
        const savedMessage = response.report_id 
          ? "Traceroute complete! Report saved automatically." 
          : "Traceroute complete!";
        setSnackbar({ open: true, message: savedMessage, severity: "success" });
        if (response.report_id) {
          loadSavedReports();
        }
      },
      (errMsg) => {
        setError(errMsg);
        setScanning(false);
        setSnackbar({ open: true, message: errMsg, severity: "error" });
      }
    );
  };

  const handleStopTraceroute = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
    }
    setScanning(false);
  };

  // Batch traceroute handler
  const handleRunBatchTraceroute = async () => {
    const targets = batchTargets
      .split('\n')
      .map(t => t.trim())
      .filter(t => t.length > 0);
    
    if (targets.length === 0) {
      setSnackbar({ open: true, message: "Please enter at least one target", severity: "error" });
      return;
    }
    
    if (targets.length > 10) {
      setSnackbar({ open: true, message: "Maximum 10 targets allowed per batch", severity: "error" });
      return;
    }
    
    setBatchScanning(true);
    setBatchResult(null);
    setError(null);
    
    try {
      const request: BatchTracerouteRequest = {
        targets,
        max_hops: maxHops,
        timeout: Math.min(timeout, 10), // Shorter timeout for batch
        queries: Math.min(queries, 3),
        use_icmp: useIcmp,
        resolve_hostnames: resolveHostnames,
        save_reports: saveReport,
      };
      
      const result = await apiClient.runBatchTraceroute(request);
      setBatchResult(result);
      
      // Reload saved reports if we saved them
      if (saveReport && result.saved_reports && result.saved_reports.length > 0) {
        loadSavedReports();
      }
      
      setSnackbar({ 
        open: true, 
        message: `Batch complete: ${result.successful}/${result.targets_traced} targets traced successfully`, 
        severity: result.failed > 0 ? "info" : "success" 
      });
    } catch (err: any) {
      setError(err.message || "Batch traceroute failed");
      setSnackbar({ open: true, message: err.message || "Batch traceroute failed", severity: "error" });
    } finally {
      setBatchScanning(false);
    }
  };

  const handleSendChat = async () => {
    if (!chatInput.trim() || !result) return;

    const userMessage = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: userMessage }]);
    setChatLoading(true);

    try {
      const response = await apiClient.chatAboutTraceroute(
        userMessage,
        {
          target: result.result.target,
          total_hops: result.result.total_hops,
          completed: result.result.completed,
          hops: result.result.hops,
          ai_analysis: result.ai_analysis,
        },
        chatMessages
      );

      if (response.error) {
        setChatMessages(prev => [...prev, { role: "assistant", content: `Error: ${response.error}` }]);
      } else {
        setChatMessages(prev => [...prev, { role: "assistant", content: response.response }]);
      }
    } catch (err: any) {
      setChatMessages(prev => [...prev, { role: "assistant", content: `Error: ${err.message}` }]);
    } finally {
      setChatLoading(false);
    }
  };

  const loadReport = async (reportId: number) => {
    try {
      const report = await apiClient.getTracerouteReport(reportId);
      setSelectedReport(report);
      setResult({
        result: report.report_data?.result || null,
        ai_analysis: report.ai_report || report.report_data?.ai_analysis || null,
        report_id: report.id,
      });
      setActiveTab(0);
    } catch (err: any) {
      setSnackbar({ open: true, message: `Failed to load report: ${err.message}`, severity: "error" });
    }
  };

  const copyCommand = async () => {
    const system = status?.platform || "windows";
    let cmd = "";
    
    if (system === "windows") {
      cmd = `tracert -h ${maxHops}${!resolveHostnames ? " -d" : ""} ${target}`;
    } else {
      cmd = `traceroute -m ${maxHops} -w ${timeout} -q ${queries}${!resolveHostnames ? " -n" : ""}${useIcmp ? " -I" : ""} ${target}`;
    }
    
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(cmd);
      } else {
        // Fallback for older browsers or non-HTTPS
        const textArea = document.createElement("textarea");
        textArea.value = cmd;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
      }
      setSnackbar({ open: true, message: "Command copied to clipboard", severity: "success" });
    } catch (err) {
      console.error("Failed to copy command:", err);
      setSnackbar({ open: true, message: "Failed to copy to clipboard", severity: "error" });
    }
  };

  // Quick targets for testing
  const quickTargets = [
    { label: "Google DNS", value: "8.8.8.8" },
    { label: "Cloudflare", value: "1.1.1.1" },
    { label: "OpenDNS", value: "208.67.222.222" },
    { label: "Google", value: "google.com" },
    { label: "GitHub", value: "github.com" },
    { label: "Amazon", value: "amazon.com" },
  ];

  // Quick chat suggestions
  const chatSuggestions = [
    "Why is there packet loss at hop 5?",
    "Is this route optimal?",
    "What's causing the high latency?",
    "Are there any security concerns?",
  ];

  // Convert hops to network graph data
  const graphData = useMemo(() => {
    if (!result?.result?.hops) return { nodes: [] as TopologyNode[], links: [] as TopologyLink[] };

    const nodes: TopologyNode[] = [];
    const links: TopologyLink[] = [];

    // Add source node (your computer)
    nodes.push({
      id: "source",
      ip: "Your Computer",
      type: "host",
      hostname: "localhost",
      riskLevel: "none",
    });

    // Add hop nodes (null-safe iteration)
    (result.result.hops || []).forEach((hop, index) => {
      const nodeId = `hop-${hop.hop_number}`;
      const isTimeout = hop.is_timeout;
      const isDestination = hop.is_destination;

      // Determine risk level based on latency and packet loss
      let riskLevel: "critical" | "high" | "medium" | "low" | "none" = "none";
      if (hop.packet_loss > 50) riskLevel = "critical";
      else if (hop.packet_loss > 20 || (hop.avg_rtt_ms && hop.avg_rtt_ms > 300)) riskLevel = "high";
      else if (hop.packet_loss > 5 || (hop.avg_rtt_ms && hop.avg_rtt_ms > 150)) riskLevel = "medium";
      else if (hop.avg_rtt_ms && hop.avg_rtt_ms > 50) riskLevel = "low";

      nodes.push({
        id: nodeId,
        ip: isTimeout ? `Hop ${hop.hop_number} (timeout)` : hop.ip_address || `Hop ${hop.hop_number}`,
        type: isDestination ? "server" : isTimeout ? "unknown" : "router",
        hostname: hop.hostname || undefined,
        riskLevel: isTimeout ? "none" : riskLevel,
        services: hop.avg_rtt_ms ? [`${hop.avg_rtt_ms.toFixed(1)}ms`] : undefined,
      });

      // Add link from previous node (null-safe access to hops array)
      const hopsArray = result.result.hops || [];
      const sourceId = index === 0 ? "source" : `hop-${hopsArray[index - 1]?.hop_number || index}`;
      links.push({
        source: sourceId,
        target: nodeId,
        protocol: "ICMP",
        packets: 3 - Math.floor((hop.packet_loss / 100) * 3),
        bidirectional: false,
      });
    });

    return { nodes, links };
  }, [result]);

  // Export results as text
  const exportResults = async () => {
    if (!result) return;
    
    let text = `Traceroute to ${result.result.target}\n`;
    text += `Target IP: ${result.result.target_ip || 'N/A'}\n`;
    text += `Total Hops: ${result.result.total_hops}\n`;
    text += `Completed: ${result.result.completed ? 'Yes' : 'No'}\n`;
    text += `Duration: ${(result.result.duration_ms / 1000).toFixed(2)}s\n`;
    text += `Platform: ${result.result.platform}\n`;
    text += `Command: ${result.result.command_used}\n\n`;
    text += `${'Hop'.padEnd(5)}${'IP Address'.padEnd(20)}${'Hostname'.padEnd(30)}${'Avg RTT'.padEnd(12)}${'Loss'.padEnd(8)}\n`;
    text += '-'.repeat(75) + '\n';
    
    (result.result.hops || []).forEach(hop => {
      const hopNum = String(hop.hop_number).padEnd(5);
      const ip = (hop.is_timeout ? '*' : hop.ip_address || '-').padEnd(20);
      const hostname = (hop.hostname || '-').substring(0, 28).padEnd(30);
      const rtt = hop.avg_rtt_ms ? `${hop.avg_rtt_ms.toFixed(1)}ms`.padEnd(12) : '-'.padEnd(12);
      const loss = `${hop.packet_loss.toFixed(0)}%`.padEnd(8);
      text += `${hopNum}${ip}${hostname}${rtt}${loss}\n`;
    });
    
    if (result.ai_analysis?.summary) {
      text += `\n\nAI Analysis Summary:\n${result.ai_analysis.summary}\n`;
    }
    
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for older browsers or non-HTTPS
        const textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-9999px";
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand("copy");
        document.body.removeChild(textArea);
      }
      setSnackbar({ open: true, message: "Results copied to clipboard", severity: "success" });
    } catch (err) {
      console.error("Failed to copy results:", err);
      setSnackbar({ open: true, message: "Failed to copy to clipboard", severity: "error" });
    }
  };

  // Delete a saved report
  const deleteReport = async (reportId: number, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await apiClient.deleteTracerouteReport(reportId);
      setSnackbar({ open: true, message: "Report deleted", severity: "success" });
      loadSavedReports();
      if (selectedReport?.id === reportId) {
        setSelectedReport(null);
        setResult(null);
      }
    } catch (err: any) {
      setSnackbar({ open: true, message: `Failed to delete: ${err.message}`, severity: "error" });
    }
  };

  if (loading) {
    return (
      <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: "80vh" }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate("/network")}>
          <BackIcon />
        </IconButton>
        <Box sx={{ 
          width: 48, 
          height: 48, 
          borderRadius: 2, 
          display: "flex", 
          alignItems: "center", 
          justifyContent: "center",
          background: `linear-gradient(135deg, #ec4899 0%, #8b5cf6 100%)`,
        }}>
          {toolMode === "traceroute" ? (
            <RouteIcon sx={{ fontSize: 28, color: "#fff" }} />
          ) : (
            <RadarIcon sx={{ fontSize: 28, color: "#fff" }} />
          )}
        </Box>
        <Box>
          <Typography variant="h4" sx={{ fontWeight: "bold" }}>
            Traceroute & Nmap Analyzer
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Network path analysis, port scanning, and service detection
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Tooltip title="Learn more">
          <Button
            component={Link}
            to={toolMode === "traceroute" ? "/learn/traceroute" : "/learn/nmap"}
            startIcon={<LearnIcon />}
            variant="outlined"
            size="small"
            sx={{ mr: 1 }}
          >
            Learn
          </Button>
        </Tooltip>
        {toolMode === "traceroute" && (
          <Chip
            icon={status?.available ? <CheckIcon /> : <ErrorIcon />}
            label={status?.available ? "Ready" : "Unavailable"}
            color={status?.available ? "success" : "error"}
          />
        )}
        {(toolMode === "nmap-scan" || toolMode === "nmap-analyze") && (
          <Chip
            icon={nmapInstalled ? <CheckIcon /> : <ErrorIcon />}
            label={nmapInstalled ? "Nmap Ready" : "Nmap Not Found"}
            color={nmapInstalled ? "success" : "warning"}
          />
        )}
      </Box>

      {/* Tool Mode Selector */}
      <Paper sx={{ p: 2, mb: 3, background: alpha(theme.palette.background.paper, 0.6) }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              onClick={() => setToolMode("traceroute")}
              sx={{
                p: 2,
                cursor: "pointer",
                border: toolMode === "traceroute" ? `2px solid #ec4899` : `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                background: toolMode === "traceroute" ? alpha("#ec4899", 0.1) : "transparent",
                transition: "all 0.2s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 4px 20px ${alpha("#ec4899", 0.2)}`,
                },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <RouteIcon sx={{ fontSize: 32, color: "#ec4899" }} />
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Traceroute
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Visualize network path & hops
                  </Typography>
                </Box>
              </Box>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              onClick={() => setToolMode("nmap-scan")}
              sx={{
                p: 2,
                cursor: "pointer",
                border: toolMode === "nmap-scan" ? `2px solid #8b5cf6` : `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                background: toolMode === "nmap-scan" ? alpha("#8b5cf6", 0.1) : "transparent",
                transition: "all 0.2s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.2)}`,
                },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <RadarIcon sx={{ fontSize: 32, color: "#8b5cf6" }} />
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Launch Nmap Scan
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Port scanning & service detection
                  </Typography>
                </Box>
              </Box>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              onClick={() => setToolMode("nmap-analyze")}
              sx={{
                p: 2,
                cursor: "pointer",
                border: toolMode === "nmap-analyze" ? `2px solid #06b6d4` : `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                background: toolMode === "nmap-analyze" ? alpha("#06b6d4", 0.1) : "transparent",
                transition: "all 0.2s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 4px 20px ${alpha("#06b6d4", 0.2)}`,
                },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <UploadIcon sx={{ fontSize: 32, color: "#06b6d4" }} />
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Analyze Nmap Output
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Upload & analyze XML/nmap files
                  </Typography>
                </Box>
              </Box>
            </Card>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Card
              onClick={() => setToolMode("nmap-command")}
              sx={{
                p: 2,
                cursor: "pointer",
                border: toolMode === "nmap-command" ? `2px solid #f59e0b` : `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                background: toolMode === "nmap-command" ? alpha("#f59e0b", 0.1) : "transparent",
                transition: "all 0.2s ease",
                "&:hover": {
                  transform: "translateY(-2px)",
                  boxShadow: `0 4px 20px ${alpha("#f59e0b", 0.2)}`,
                },
              }}
            >
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <TerminalIcon sx={{ fontSize: 32, color: "#f59e0b" }} />
                <Box>
                  <Typography variant="subtitle1" sx={{ fontWeight: 700 }}>
                    Nmap Command Builder
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Generate CLI commands for Nmap
                  </Typography>
                </Box>
              </Box>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* ================================================================ */}
      {/* TRACEROUTE MODE */}
      {/* ================================================================ */}
      {toolMode === "traceroute" && (
        <>
          {/* Docker Network Notice */}
          <Alert 
            severity="warning" 
            sx={{ mb: 3 }}
            icon={<WarningIcon />}
          >
            <Typography variant="body2" sx={{ fontWeight: 500 }}>
              <strong>Docker Desktop Limitation:</strong> On Windows/macOS, Docker Desktop's NAT hides intermediate network hops. 
              You'll see the Docker bridge (172.18.x.x) then the destination, but not your router or ISP hops. 
              For full network path visibility, run <code>tracert [target]</code> (Windows) or <code>traceroute [target]</code> (macOS/Linux) 
              directly from your terminal.
            </Typography>
          </Alert>

          {/* Main Content */}
          <Grid container spacing={3}>
            {/* Left Panel - Configuration */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ p: 3, mb: 3 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="h6">
                    Scan Configuration
                  </Typography>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={batchMode}
                        onChange={(e) => {
                          setBatchMode(e.target.checked);
                          setBatchResult(null);
                          setResult(null);
                        }}
                        disabled={scanning || batchScanning}
                        size="small"
                      />
                    }
                    label={
                      <Typography variant="caption" sx={{ fontWeight: "bold", color: batchMode ? "primary.main" : "text.secondary" }}>
                        Batch Mode
                      </Typography>
                    }
                  />
                </Box>

            {/* Single Target Mode */}
            {!batchMode && (
              <>
                <TextField
                  fullWidth
                  label="Target (hostname or IP)"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="e.g., google.com or 8.8.8.8"
                  sx={{ mb: 2 }}
                  disabled={scanning}
                />

                {/* Quick Targets */}
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 3 }}>
                  {quickTargets.map((qt) => (
                    <Chip
                      key={qt.value}
                      label={qt.label}
                      onClick={() => setTarget(qt.value)}
                      size="small"
                      variant={target === qt.value ? "filled" : "outlined"}
                      color="primary"
                      disabled={scanning}
                    />
                  ))}
                </Box>
              </>
            )}

            {/* Batch Mode Input */}
            {batchMode && (
              <>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="Targets (one per line, max 10)"
                  value={batchTargets}
                  onChange={(e) => setBatchTargets(e.target.value)}
                  placeholder={"google.com\ngithub.com\namazon.com\n8.8.8.8\n1.1.1.1"}
                  sx={{ mb: 2 }}
                  disabled={batchScanning}
                  helperText={`${batchTargets.split('\n').filter(t => t.trim()).length} target(s) entered`}
                />

                {/* Quick Fill for Batch */}
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 3 }}>
                  <Chip
                    label="Popular Sites"
                    onClick={() => setBatchTargets("google.com\ngithub.com\namazon.com\nmicrosoft.com\napple.com")}
                    size="small"
                    variant="outlined"
                    color="primary"
                    disabled={batchScanning}
                  />
                  <Chip
                    label="DNS Servers"
                    onClick={() => setBatchTargets("8.8.8.8\n1.1.1.1\n208.67.222.222\n9.9.9.9\n4.2.2.1")}
                    size="small"
                    variant="outlined"
                    color="secondary"
                    disabled={batchScanning}
                  />
                  <Chip
                    label="Cloud Providers"
                    onClick={() => setBatchTargets("aws.amazon.com\nazure.microsoft.com\ncloud.google.com\ncloudflare.com")}
                    size="small"
                    variant="outlined"
                    color="info"
                    disabled={batchScanning}
                  />
                </Box>
              </>
            )}

            {/* Settings Toggle */}
            <Button
              variant="text"
              onClick={() => setShowSettings(!showSettings)}
              startIcon={showSettings ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              sx={{ mb: 2 }}
            >
              Advanced Settings
            </Button>

            <Collapse in={showSettings}>
              <Box sx={{ mb: 3 }}>
                {/* Max Hops */}
                <Typography variant="body2" gutterBottom>
                  Max Hops: {maxHops}
                </Typography>
                <Slider
                  value={maxHops}
                  onChange={(_, v) => setMaxHops(v as number)}
                  min={5}
                  max={64}
                  disabled={scanning}
                  sx={{ mb: 2 }}
                />

                {/* Timeout */}
                <Typography variant="body2" gutterBottom>
                  Timeout per Hop: {timeout}s
                </Typography>
                <Slider
                  value={timeout}
                  onChange={(_, v) => setTimeout(v as number)}
                  min={1}
                  max={30}
                  disabled={scanning}
                  sx={{ mb: 2 }}
                />

                {/* Queries (non-Windows) */}
                {status?.features.custom_queries && (
                  <>
                    <Typography variant="body2" gutterBottom>
                      Queries per Hop: {queries}
                    </Typography>
                    <Slider
                      value={queries}
                      onChange={(_, v) => setQueries(v as number)}
                      min={1}
                      max={10}
                      disabled={scanning}
                      sx={{ mb: 2 }}
                    />
                  </>
                )}

                {/* Switches */}
                <FormControlLabel
                  control={
                    <Switch
                      checked={resolveHostnames}
                      onChange={(e) => setResolveHostnames(e.target.checked)}
                      disabled={scanning}
                    />
                  }
                  label="Resolve Hostnames"
                />

                {status?.features.icmp_mode && (
                  <FormControlLabel
                    control={
                      <Switch
                        checked={useIcmp}
                        onChange={(e) => setUseIcmp(e.target.checked)}
                        disabled={scanning}
                      />
                    }
                    label="Use ICMP (requires root)"
                  />
                )}

                <Divider sx={{ my: 2 }} />

                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                  All scans are automatically saved
                </Typography>

                <TextField
                  fullWidth
                  label="Report Title (optional)"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  size="small"
                  disabled={scanning}
                  helperText="Give your scan a name for easy reference"
                />
              </Box>
            </Collapse>

            {/* Action Buttons */}
            <Box sx={{ display: "flex", gap: 2 }}>
              {/* Single Mode Buttons */}
              {!batchMode && (
                <>
                  {scanning ? (
                    <Button
                      variant="contained"
                      color="error"
                      onClick={handleStopTraceroute}
                      startIcon={<StopIcon />}
                      fullWidth
                    >
                      Stop
                    </Button>
                  ) : (
                    <Button
                      variant="contained"
                      onClick={handleRunTraceroute}
                      startIcon={<PlayIcon />}
                      fullWidth
                      disabled={!status?.available || !target.trim()}
                      sx={{
                        bgcolor: "#ec4899",
                        "&:hover": { bgcolor: "#db2777" },
                      }}
                    >
                      Run Traceroute
                    </Button>
                  )}
                  <Tooltip title="Copy command">
                    <IconButton onClick={copyCommand} disabled={!target.trim()}>
                      <CopyIcon />
                    </IconButton>
                  </Tooltip>
                </>
              )}
              
              {/* Batch Mode Buttons */}
              {batchMode && (
                <Button
                  variant="contained"
                  onClick={handleRunBatchTraceroute}
                  startIcon={batchScanning ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
                  fullWidth
                  disabled={!status?.available || batchScanning || batchTargets.split('\n').filter(t => t.trim()).length === 0}
                  sx={{
                    bgcolor: "#8b5cf6",
                    "&:hover": { bgcolor: "#7c3aed" },
                  }}
                >
                  {batchScanning ? "Tracing..." : "Run Batch Traceroute"}
                </Button>
              )}
            </Box>
          </Paper>

          {/* Saved Reports */}
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h6">Saved Reports</Typography>
              <IconButton onClick={loadSavedReports} size="small">
                <RefreshIcon />
              </IconButton>
            </Box>

            {loadingReports ? (
              <Box sx={{ display: "flex", justifyContent: "center", p: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : savedReports.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                No saved reports yet
              </Typography>
            ) : (
              <List dense>
                {savedReports.slice(0, 5).map((report) => (
                  <ListItem
                    key={report.id}
                    secondaryAction={
                      <Box>
                        <IconButton size="small" onClick={() => loadReport(report.id)}>
                          <ViewIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={(e) => deleteReport(report.id, e)} color="error">
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Box>
                    }
                  >
                    <ListItemIcon>
                      <HistoryIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary={report.title}
                      secondary={new Date(report.created_at).toLocaleString()}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>
        </Grid>

        {/* Right Panel - Results */}
        <Grid item xs={12} md={8}>
          {/* Live Progress (Single Mode) */}
          {scanning && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <CircularProgress size={24} />
                <Typography variant="h6">Tracing route to {target}...</Typography>
              </Box>
              <Box sx={{ fontFamily: "monospace", bgcolor: "#1e1e1e", p: 2, borderRadius: 1 }}>
                {liveHops.map((hop, i) => (
                  <Typography key={i} variant="body2" sx={{ color: "#fff" }}>
                    {hop.raw}
                  </Typography>
                ))}
                {liveHops.length === 0 && (
                  <Typography variant="body2" sx={{ color: "#888" }}>
                    Waiting for first hop...
                  </Typography>
                )}
              </Box>
            </Paper>
          )}

          {/* Batch Progress */}
          {batchScanning && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <CircularProgress size={24} sx={{ color: "#8b5cf6" }} />
                <Typography variant="h6">Running batch traceroute...</Typography>
              </Box>
              <Typography variant="body2" color="text.secondary">
                Tracing routes to {batchTargets.split('\n').filter(t => t.trim()).length} targets in parallel.
                This may take several minutes depending on the number of targets.
              </Typography>
              <LinearProgress sx={{ mt: 2, bgcolor: "grey.800", "& .MuiLinearProgress-bar": { bgcolor: "#8b5cf6" } }} />
            </Paper>
          )}

          {/* Batch Results */}
          {batchResult && batchMode && (
            <Paper sx={{ p: 3, mb: 3 }}>
              {/* Batch Summary Header */}
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                <Typography variant="h6">
                  Batch Results
                </Typography>
                <Chip
                  label={`${batchResult.successful}/${batchResult.targets_traced} Successful`}
                  color={batchResult.failed === 0 ? "success" : "warning"}
                  size="small"
                />
                {batchResult.failed > 0 && (
                  <Chip
                    label={`${batchResult.failed} Failed`}
                    color="error"
                    size="small"
                  />
                )}
              </Box>

              {/* Combined Network Topology */}
              {batchResult.combined_topology && batchResult.combined_topology.nodes.length > 1 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: "bold" }}>
                    Combined Network Topology
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    All traced paths visualized together. Node colors indicate latency/packet loss levels.
                    Shared infrastructure is highlighted where multiple paths converge.
                  </Typography>
                  <NetworkTopologyGraph
                    nodes={batchResult.combined_topology.nodes.map(n => ({
                      id: n.id,
                      ip: n.ip,
                      type: n.type,
                      hostname: n.hostname,
                      riskLevel: n.riskLevel,
                      services: n.targets ? [`Routes: ${n.targets.join(', ')}`] : undefined,
                    }))}
                    links={batchResult.combined_topology.links.map(l => ({
                      source: l.source,
                      target: l.target,
                      protocol: l.protocol,
                      packets: l.packets,
                    }))}
                    title="Combined Network Paths"
                    height={450}
                  />
                </Box>
              )}

              {/* Comparative Analysis */}
              {batchResult.comparative_analysis && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: "bold", display: "flex", alignItems: "center", gap: 1 }}>
                    <SmartToyIcon fontSize="small" />
                    Comparative Analysis
                  </Typography>
                  
                  <Alert severity="info" sx={{ mb: 2 }}>
                    {batchResult.comparative_analysis.summary || "Analysis complete"}
                  </Alert>

                  {/* Shared Infrastructure */}
                  {batchResult.comparative_analysis.shared_infrastructure && (
                    <Card variant="outlined" sx={{ mb: 2 }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>Shared Infrastructure</Typography>
                        {(batchResult.comparative_analysis.shared_infrastructure.common_hops || []).length > 0 && (
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="text.secondary">Common Hops:</Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                              {(batchResult.comparative_analysis.shared_infrastructure.common_hops || []).map((hop, i) => (
                                <Chip key={i} label={hop} size="small" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}
                        {(batchResult.comparative_analysis.shared_infrastructure.shared_isps || []).length > 0 && (
                          <Box sx={{ mb: 1 }}>
                            <Typography variant="caption" color="text.secondary">Shared ISPs:</Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                              {(batchResult.comparative_analysis.shared_infrastructure.shared_isps || []).map((isp, i) => (
                                <Chip key={i} label={isp} size="small" color="primary" variant="outlined" />
                              ))}
                            </Box>
                          </Box>
                        )}
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          {batchResult.comparative_analysis.shared_infrastructure.convergence_analysis || ""}
                        </Typography>
                      </CardContent>
                    </Card>
                  )}

                  {/* Performance Comparison */}
                  {batchResult.comparative_analysis.performance_comparison && (
                    <Card variant="outlined" sx={{ mb: 2 }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>Performance Comparison</Typography>
                        <Grid container spacing={2}>
                          <Grid item xs={6}>
                            <Typography variant="caption" color="text.secondary">Fastest</Typography>
                            <Typography variant="body2" sx={{ fontWeight: "bold", color: "success.main" }}>
                              {batchResult.comparative_analysis.performance_comparison.fastest_target || "N/A"}
                            </Typography>
                          </Grid>
                          <Grid item xs={6}>
                            <Typography variant="caption" color="text.secondary">Slowest</Typography>
                            <Typography variant="body2" sx={{ fontWeight: "bold", color: "warning.main" }}>
                              {batchResult.comparative_analysis.performance_comparison.slowest_target || "N/A"}
                            </Typography>
                          </Grid>
                        </Grid>
                        <Typography variant="body2" sx={{ mt: 1 }}>
                          {batchResult.comparative_analysis.performance_comparison.hop_count_analysis || ""}
                        </Typography>
                      </CardContent>
                    </Card>
                  )}

                  {/* Security Observations */}
                  {batchResult.comparative_analysis.security_observations && batchResult.comparative_analysis.security_observations.length > 0 && (
                    <Card variant="outlined" sx={{ mb: 2 }}>
                      <CardContent>
                        <Typography variant="subtitle2" sx={{ mb: 1 }}>Security Observations</Typography>
                        {batchResult.comparative_analysis.security_observations.map((obs, i) => (
                          <Alert 
                            key={i} 
                            severity={obs.severity === "high" ? "error" : obs.severity === "medium" ? "warning" : "info"}
                            sx={{ mb: 1 }}
                          >
                            <Typography variant="body2" sx={{ fontWeight: "bold" }}>{obs.observation || ""}</Typography>
                            <Typography variant="caption">
                              Affected: {(obs.affected_targets || []).join(", ")}
                            </Typography>
                          </Alert>
                        ))}
                      </CardContent>
                    </Card>
                  )}

                  {/* Recommendations */}
                  {batchResult.comparative_analysis.recommendations && batchResult.comparative_analysis.recommendations.length > 0 && (
                    <Box>
                      <Typography variant="subtitle2" sx={{ mb: 1 }}>Recommendations</Typography>
                      <List dense>
                        {batchResult.comparative_analysis.recommendations.map((rec, i) => (
                          <ListItem key={i}>
                            <ListItemIcon sx={{ minWidth: 32 }}>
                              <CheckIcon fontSize="small" color="primary" />
                            </ListItemIcon>
                            <ListItemText primary={rec} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Box>
              )}

              {/* Individual Results Table */}
              <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: "bold", mt: 2 }}>
                Individual Traces
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Target</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>Hops</TableCell>
                      <TableCell>Completed</TableCell>
                      <TableCell>Duration</TableCell>
                      <TableCell>Risk</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(batchResult.results || []).map((r, i) => (
                      <TableRow 
                        key={i}
                        sx={{ 
                          cursor: r.success ? "pointer" : "default",
                          "&:hover": r.success ? { bgcolor: "action.hover" } : {},
                        }}
                        onClick={() => {
                          if (r.success && r.result && r.ai_analysis) {
                            setResult({
                              result: r.result,
                              ai_analysis: r.ai_analysis,
                            });
                            setBatchMode(false);
                          }
                        }}
                      >
                        <TableCell sx={{ fontFamily: "monospace" }}>{r.target}</TableCell>
                        <TableCell>
                          {r.success ? (
                            <Chip label="Success" size="small" color="success" />
                          ) : (
                            <Chip label="Failed" size="small" color="error" />
                          )}
                        </TableCell>
                        <TableCell>{r.result?.total_hops || "-"}</TableCell>
                        <TableCell>
                          {r.result?.completed ? (
                            <CheckIcon fontSize="small" color="success" />
                          ) : r.success ? (
                            <WarningIcon fontSize="small" color="warning" />
                          ) : "-"}
                        </TableCell>
                        <TableCell>
                          {r.result?.duration_ms ? `${(r.result.duration_ms / 1000).toFixed(1)}s` : "-"}
                        </TableCell>
                        <TableCell>
                          {r.ai_analysis?.risk_score !== undefined ? (
                            <Chip 
                              label={r.ai_analysis.risk_score} 
                              size="small" 
                              color={
                                r.ai_analysis.risk_score >= 70 ? "error" :
                                r.ai_analysis.risk_score >= 40 ? "warning" : "success"
                              }
                            />
                          ) : "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {/* Validation Errors */}
              {batchResult.validation_errors && batchResult.validation_errors.length > 0 && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  <Typography variant="subtitle2">Could not resolve:</Typography>
                  {batchResult.validation_errors.map((err, i) => (
                    <Typography key={i} variant="body2">
                      • {err.target}: {err.error}
                    </Typography>
                  ))}
                </Alert>
              )}
            </Paper>
          )}

          {/* Single Results */}
          {result && result.result && !batchMode && (
            <Paper sx={{ p: 3 }}>
              {/* Result Header */}
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
                <Typography variant="h6">
                  Results: {result.result.target}
                  {result.result.target_ip && result.result.target_ip !== result.result.target && (
                    <Typography component="span" color="text.secondary" sx={{ ml: 1 }}>
                      ({result.result.target_ip})
                    </Typography>
                  )}
                </Typography>
                <Chip
                  label={result.result.completed ? "Reached" : "Incomplete"}
                  color={result.result.completed ? "success" : "warning"}
                  size="small"
                />
                <Chip
                  label={`${result.result.total_hops} hops`}
                  size="small"
                  variant="outlined"
                />
                <Chip
                  label={`${(result.result.duration_ms / 1000).toFixed(1)}s`}
                  size="small"
                  variant="outlined"
                />
                <Box sx={{ flex: 1 }} />
                <Tooltip title="Export results">
                  <IconButton onClick={exportResults} color="default">
                    <DownloadIcon />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Ask AI about this trace">
                  <IconButton onClick={() => setShowChat(true)} color="primary">
                    <ChatIcon />
                  </IconButton>
                </Tooltip>
              </Box>

              {/* Tabs */}
              <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 2 }}>
                <Tab label="Path Visualization" />
                <Tab label="Network Graph" icon={<HubIcon />} iconPosition="start" />
                <Tab label="Latency Chart" />
                <Tab label="AI Analysis" />
                <Tab label="Raw Data" />
              </Tabs>

              {/* Tab Panels */}
              {activeTab === 0 && (
                <PathVisualization
                  hops={result.result.hops}
                  target={result.result.target}
                  completed={result.result.completed}
                />
              )}

              {activeTab === 1 && (
                <Box>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Interactive network topology showing the route from your computer to {result.result.target}.
                    Drag nodes to rearrange. Colors indicate latency/packet loss levels.
                  </Typography>
                  <NetworkTopologyGraph
                    nodes={graphData.nodes}
                    links={graphData.links}
                    title={`Route to ${result.result.target}`}
                    height={500}
                  />
                </Box>
              )}

              {activeTab === 2 && <LatencyChart hops={result.result.hops} />}

              {activeTab === 3 && <AIAnalysisPanel analysis={result.ai_analysis} />}

              {activeTab === 4 && (
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Hop</TableCell>
                        <TableCell>IP Address</TableCell>
                        <TableCell>Hostname</TableCell>
                        <TableCell>RTT (ms)</TableCell>
                        <TableCell>Avg RTT</TableCell>
                        <TableCell>Loss</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(result.result.hops || []).map((hop) => (
                        <TableRow key={hop.hop_number}>
                          <TableCell>{hop.hop_number}</TableCell>
                          <TableCell>
                            {hop.is_timeout ? "*" : hop.ip_address || "-"}
                          </TableCell>
                          <TableCell>{hop.hostname || "-"}</TableCell>
                          <TableCell>
                            {hop.is_timeout
                              ? "*"
                              : (hop.rtt_ms || []).map((r) => r.toFixed(1)).join(" / ")}
                          </TableCell>
                          <TableCell>
                            {hop.avg_rtt_ms ? hop.avg_rtt_ms.toFixed(1) : "-"}
                          </TableCell>
                          <TableCell>
                            {hop.packet_loss > 0 ? `${hop.packet_loss.toFixed(0)}%` : "0%"}
                          </TableCell>
                          <TableCell>
                            {hop.is_destination ? (
                              <Chip label="Destination" size="small" color="success" />
                            ) : hop.is_timeout ? (
                              <Chip label="Timeout" size="small" />
                            ) : (
                              <Chip label="OK" size="small" color="primary" variant="outlined" />
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}
            </Paper>
          )}

          {/* No results placeholder */}
          {!result && !scanning && !batchMode && !batchScanning && (
            <Paper sx={{ p: 6, textAlign: "center" }}>
              <RouteIcon sx={{ fontSize: 80, color: "#ec4899", opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                Enter a target and run a traceroute to visualize the network path
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Traceroute helps you understand the route packets take across the network
              </Typography>
            </Paper>
          )}

          {/* Batch mode placeholder */}
          {batchMode && !batchResult && !batchScanning && (
            <Paper sx={{ p: 6, textAlign: "center" }}>
              <HubIcon sx={{ fontSize: 80, color: "#8b5cf6", opacity: 0.3, mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                Batch Traceroute Mode
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Enter multiple targets (one per line) to trace routes to all of them simultaneously.
                Results will show a combined network topology and comparative analysis.
              </Typography>
            </Paper>
          )}
        </Grid>
      </Grid>
        </>
      )}

      {/* ================================================================ */}
      {/* NMAP SCAN MODE */}
      {/* ================================================================ */}
      {toolMode === "nmap-scan" && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <RadarIcon sx={{ color: "#8b5cf6" }} />
                Nmap Scan Configuration
              </Typography>

              {!nmapInstalled && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  Nmap is not installed on the server. You can still analyze existing Nmap output files.
                </Alert>
              )}

              <TextField
                fullWidth
                label="Target (IP, hostname, or CIDR)"
                value={nmapTarget}
                onChange={(e) => setNmapTarget(e.target.value)}
                placeholder="e.g., 192.168.1.1, scanme.nmap.org, 10.0.0.0/24"
                sx={{ mb: 2 }}
                disabled={nmapScanning || !nmapInstalled}
              />

              {/* Quick targets */}
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                {[
                  { label: "scanme.nmap.org", value: "scanme.nmap.org" },
                  { label: "localhost", value: "127.0.0.1" },
                  { label: "Google DNS", value: "8.8.8.8" },
                ].map((qt) => (
                  <Chip
                    key={qt.value}
                    label={qt.label}
                    onClick={() => setNmapTarget(qt.value)}
                    size="small"
                    variant={nmapTarget === qt.value ? "filled" : "outlined"}
                    color="secondary"
                    disabled={nmapScanning || !nmapInstalled}
                  />
                ))}
              </Box>

              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel>Scan Type</InputLabel>
                <Select
                  value={nmapSelectedScanType}
                  label="Scan Type"
                  onChange={(e) => setNmapSelectedScanType(e.target.value)}
                  disabled={nmapScanning || !nmapInstalled}
                >
                  {nmapScanTypeOptions.map((st) => (
                    <MenuItem key={st.id} value={st.id}>
                      <Box>
                        <Typography variant="body2">{st.name}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {st.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>

              <TextField
                fullWidth
                label="Custom Ports (optional)"
                value={nmapCustomPorts}
                onChange={(e) => setNmapCustomPorts(e.target.value)}
                placeholder="e.g., 22,80,443 or 1-1000"
                sx={{ mb: 2 }}
                disabled={nmapScanning || !nmapInstalled}
              />

              <TextField
                fullWidth
                label="Scan Title (optional)"
                value={nmapScanTitle}
                onChange={(e) => setNmapScanTitle(e.target.value)}
                placeholder="e.g., Production Server Scan"
                sx={{ mb: 2 }}
                disabled={nmapScanning}
              />

              {/* NSE Script Options Accordion */}
              <Accordion 
                expanded={showScriptOptions}
                onChange={(_, expanded) => setShowScriptOptions(expanded)}
                sx={{ 
                  mb: 2, 
                  '&:before': { display: 'none' },
                  boxShadow: 'none',
                  border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                  borderRadius: 1,
                }}
              >
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SecurityIcon fontSize="small" sx={{ color: '#8b5cf6' }} />
                    <Typography variant="subtitle2">
                      NSE Scripts
                      {(selectedScriptCategories.length > 0 || selectedScripts.length > 0) && (
                        <Chip 
                          label={`${selectedScriptCategories.length + selectedScripts.length} selected`}
                          size="small"
                          color="secondary"
                          sx={{ ml: 1 }}
                        />
                      )}
                    </Typography>
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
                    Add vulnerability detection and other NSE scripts to your scan
                  </Typography>

                  {/* Script Categories */}
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>Script Categories</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
                    {nseScriptCategories.map((cat) => (
                      <Tooltip key={cat.id} title={
                        <Box>
                          <Typography variant="body2">{cat.description}</Typography>
                          {cat.warning && (
                            <Typography variant="caption" color="warning.main" sx={{ mt: 1, display: 'block' }}>
                              ⚠️ {cat.warning}
                            </Typography>
                          )}
                        </Box>
                      }>
                        <Chip
                          label={cat.name}
                          size="small"
                          variant={selectedScriptCategories.includes(cat.id) ? "filled" : "outlined"}
                          color={cat.warning ? "warning" : "secondary"}
                          onClick={() => {
                            setSelectedScriptCategories(prev => 
                              prev.includes(cat.id) 
                                ? prev.filter(c => c !== cat.id)
                                : [...prev, cat.id]
                            );
                          }}
                          disabled={nmapScanning}
                        />
                      </Tooltip>
                    ))}
                  </Box>

                  {/* Individual Popular Scripts */}
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>Popular Scripts</Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {nseScripts.slice(0, 15).map((script) => (
                      <Tooltip key={script.id} title={script.description}>
                        <Chip
                          label={script.name}
                          size="small"
                          variant={selectedScripts.includes(script.id) ? "filled" : "outlined"}
                          color={script.category === 'vuln' ? 'error' : 'default'}
                          onClick={() => {
                            setSelectedScripts(prev => 
                              prev.includes(script.id) 
                                ? prev.filter(s => s !== script.id)
                                : [...prev, script.id]
                            );
                          }}
                          disabled={nmapScanning}
                        />
                      </Tooltip>
                    ))}
                  </Box>

                  {(selectedScriptCategories.length > 0 || selectedScripts.length > 0) && (
                    <Button
                      size="small"
                      onClick={() => {
                        setSelectedScriptCategories([]);
                        setSelectedScripts([]);
                      }}
                      sx={{ mt: 1 }}
                    >
                      Clear All Scripts
                    </Button>
                  )}
                </AccordionDetails>
              </Accordion>

              <Button
                fullWidth
                variant="contained"
                color="secondary"
                startIcon={nmapScanning ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
                onClick={handleRunNmapScan}
                disabled={nmapScanning || !nmapTarget.trim() || !nmapInstalled}
                sx={{
                  py: 1.5,
                  background: `linear-gradient(135deg, #8b5cf6 0%, #6366f1 100%)`,
                }}
              >
                {nmapScanning ? "Scanning..." : "Start Nmap Scan"}
              </Button>
            </Paper>
          </Grid>

          <Grid item xs={12} md={8}>
            {nmapScanning && (
              <Paper sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <CircularProgress size={24} />
                  <Typography variant="h6">Scanning {nmapTarget}...</Typography>
                </Box>
                <LinearProgress />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                  This may take a while depending on the scan type and target size.
                </Typography>
              </Paper>
            )}

            {nmapResult && !nmapScanning && (
              <Paper sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckIcon sx={{ color: "success.main" }} />
                    Scan Complete
                  </Typography>
                  <NmapExportOptions
                    hosts={getNmapSummary(nmapResult)?.hosts || []}
                    findings={(getNmapSummary(nmapResult)?.findings || []) as any}
                    summary={getNmapSummary(nmapResult)?.summary}
                    scanTarget={nmapTarget}
                  />
                </Box>

                <Tabs value={nmapActiveTab} onChange={(_, v) => setNmapActiveTab(v)} sx={{ mb: 2 }}>
                  <Tab label="Summary" />
                  <Tab label="Network Map" icon={<TopologyIcon fontSize="small" />} iconPosition="start" />
                  <Tab label="Hosts" />
                  <Tab 
                    label={
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        Findings
                        {(() => {
                          const data = getNmapSummary(nmapResult);
                          const highCount = data?.findings?.filter((f: any) => f.severity === 'high' || f.severity === 'critical').length || 0;
                          return highCount > 0 ? (
                            <Chip label={highCount} size="small" color="error" sx={{ ml: 0.5, height: 20 }} />
                          ) : null;
                        })()}
                      </Box>
                    }
                    icon={<FindingsIcon fontSize="small" />} 
                    iconPosition="start" 
                  />
                  <Tab label="AI Analysis" />
                </Tabs>

                {nmapActiveTab === 0 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <Grid container spacing={2}>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="primary">
                                {data?.summary?.hosts_up || data?.hosts?.length || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Hosts Up
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="warning.main">
                                {data?.summary?.open_ports || data?.hosts?.reduce((acc: number, h: any) => acc + (h.ports?.filter((p: any) => p.state === "open").length || 0), 0) || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Open Ports
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="error.main">
                                {data?.findings?.filter((f: any) => f.severity === 'high' || f.severity === 'critical').length || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                High-Risk Findings
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="success.main">
                                {Object.keys(data?.summary?.services_detected || {}).length || [...new Set(data?.hosts?.flatMap((h: any) => h.ports?.map((p: any) => p.service).filter(Boolean)) || [])].length}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Services
                              </Typography>
                            </Card>
                          </Grid>
                        </Grid>
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 1 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <NmapNetworkGraph
                          hosts={data?.hosts || []}
                          findings={data?.findings || []}
                          onHostClick={(host) => {
                            setSelectedHost(host);
                            setHostDrawerOpen(true);
                          }}
                          height={500}
                        />
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 2 && (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>IP Address</TableCell>
                          <TableCell>Hostname</TableCell>
                          <TableCell>OS</TableCell>
                          <TableCell>State</TableCell>
                          <TableCell>Open Ports</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {(() => {
                          const data = getNmapSummary(nmapResult);
                          return (data?.hosts || []).map((host: any, idx: number) => (
                            <TableRow key={idx} hover sx={{ cursor: "pointer" }} onClick={() => { setSelectedHost(host); setHostDrawerOpen(true); }}>
                              <TableCell>
                                <Typography sx={{ fontFamily: "monospace" }}>{host.ip || host.address || "-"}</Typography>
                              </TableCell>
                              <TableCell>{host.hostname || host.hostnames?.[0] || "-"}</TableCell>
                              <TableCell>
                                <Tooltip title={host.os_guess || "Unknown"}>
                                  <Typography variant="body2" sx={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                    {host.os_guess ? (host.os_guess.length > 20 ? host.os_guess.substring(0, 20) + "..." : host.os_guess) : "-"}
                                  </Typography>
                                </Tooltip>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={host.state || host.status || "up"}
                                  size="small"
                                  color={host.state === "up" || host.status === "up" || !host.state ? "success" : "default"}
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={host.ports?.filter((p: any) => p.state === "open").length || host.open_ports || 0}
                                  size="small"
                                  color="primary"
                                  variant="outlined"
                                />
                              </TableCell>
                              <TableCell>
                                <IconButton size="small" onClick={(e) => { e.stopPropagation(); setSelectedHost(host); setHostDrawerOpen(true); }}>
                                  <ViewIcon fontSize="small" />
                                </IconButton>
                              </TableCell>
                            </TableRow>
                          ));
                        })()}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}

                {nmapActiveTab === 3 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <NmapFindingsTab
                          findings={data?.findings || []}
                          onHostClick={(hostIp) => {
                            const host = data?.hosts?.find((h: any) => h.ip === hostIp || h.address === hostIp);
                            if (host) {
                              setSelectedHost(host);
                              setHostDrawerOpen(true);
                            }
                          }}
                        />
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 4 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      if (!data?.ai_analysis) {
                        return (
                          <Typography color="text.secondary">
                            No AI analysis available for this scan.
                          </Typography>
                        );
                      }
                      return (
                        <ReactMarkdown
                          components={{
                            code: ({ className, children }) => (
                              <ChatCodeBlock className={className} theme={theme}>
                                {children}
                              </ChatCodeBlock>
                            ),
                          }}
                        >
                          {typeof data.ai_analysis === 'string' ? data.ai_analysis : JSON.stringify(data.ai_analysis, null, 2)}
                        </ReactMarkdown>
                      );
                    })()}
                  </Box>
                )}
              </Paper>
            )}

            {!nmapScanning && !nmapResult && (
              <Paper sx={{ p: 4, textAlign: "center" }}>
                <RadarIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Configure and run an Nmap scan
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Results will appear here with AI-powered analysis
                </Typography>
              </Paper>
            )}
          </Grid>
        </Grid>
      )}

      {/* ================================================================ */}
      {/* NMAP ANALYZE MODE */}
      {/* ================================================================ */}
      {toolMode === "nmap-analyze" && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <UploadIcon sx={{ color: "#06b6d4" }} />
                Upload Nmap Output
              </Typography>

              <Box
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleNmapFileDrop}
                sx={{
                  border: `2px dashed ${alpha("#06b6d4", 0.4)}`,
                  borderRadius: 2,
                  p: 4,
                  textAlign: "center",
                  cursor: "pointer",
                  transition: "all 0.2s ease",
                  "&:hover": {
                    borderColor: "#06b6d4",
                    bgcolor: alpha("#06b6d4", 0.05),
                  },
                  mb: 2,
                }}
                onClick={() => nmapFileInputRef.current?.click()}
              >
                <input
                  type="file"
                  ref={nmapFileInputRef}
                  style={{ display: "none" }}
                  accept=".xml,.nmap,.gnmap"
                  onChange={handleNmapFileSelect}
                />
                <UploadIcon sx={{ fontSize: 48, color: "#06b6d4", mb: 1 }} />
                <Typography variant="body1" sx={{ fontWeight: 600 }}>
                  Drag & drop Nmap files here
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  or click to browse (XML, .nmap, .gnmap)
                </Typography>
              </Box>

              {nmapFiles.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  {nmapFiles.map((file, idx) => (
                    <Chip
                      key={idx}
                      label={file.name}
                      onDelete={() => setNmapFiles(nmapFiles.filter((_, i) => i !== idx))}
                      sx={{ mr: 1, mb: 1 }}
                    />
                  ))}
                </Box>
              )}

              <TextField
                fullWidth
                label="Report Title (optional)"
                value={nmapScanTitle}
                onChange={(e) => setNmapScanTitle(e.target.value)}
                placeholder="e.g., Network Audit Q1 2026"
                sx={{ mb: 3 }}
                disabled={nmapAnalyzing}
              />

              <Button
                fullWidth
                variant="contained"
                startIcon={nmapAnalyzing ? <CircularProgress size={20} color="inherit" /> : <PlayIcon />}
                onClick={handleAnalyzeNmapFile}
                disabled={nmapAnalyzing || nmapFiles.length === 0}
                sx={{
                  py: 1.5,
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                }}
              >
                {nmapAnalyzing ? "Analyzing..." : "Analyze File"}
              </Button>

              <Divider sx={{ my: 3 }} />

              <Typography variant="subtitle2" sx={{ mb: 1 }}>
                Supported Formats:
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemIcon><CheckIcon sx={{ color: "success.main" }} /></ListItemIcon>
                  <ListItemText primary="Nmap XML (-oX)" secondary="Full structured output" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon sx={{ color: "success.main" }} /></ListItemIcon>
                  <ListItemText primary="Nmap Normal (-oN)" secondary="Human-readable output" />
                </ListItem>
                <ListItem>
                  <ListItemIcon><CheckIcon sx={{ color: "success.main" }} /></ListItemIcon>
                  <ListItemText primary="Grepable (-oG)" secondary="Easy to parse format" />
                </ListItem>
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={8}>
            {nmapAnalyzing && (
              <Paper sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <CircularProgress size={24} />
                  <Typography variant="h6">Analyzing Nmap output...</Typography>
                </Box>
                <LinearProgress />
              </Paper>
            )}

            {nmapResult && !nmapAnalyzing && (
              <Paper sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                  <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CheckIcon sx={{ color: "success.main" }} />
                    Analysis Complete
                  </Typography>
                  <NmapExportOptions
                    hosts={getNmapSummary(nmapResult)?.hosts || []}
                    findings={(getNmapSummary(nmapResult)?.findings || []) as any}
                    summary={getNmapSummary(nmapResult)?.summary}
                    scanTarget={nmapFiles[0]?.name || "Uploaded file"}
                  />
                </Box>

                <Tabs value={nmapActiveTab} onChange={(_, v) => setNmapActiveTab(v)} sx={{ mb: 2 }}>
                  <Tab label="Summary" />
                  <Tab label="Network Map" icon={<TopologyIcon fontSize="small" />} iconPosition="start" />
                  <Tab label="Hosts" />
                  <Tab 
                    label={
                      <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                        Findings
                        {(() => {
                          const data = getNmapSummary(nmapResult);
                          const highCount = data?.findings?.filter((f: any) => f.severity === 'high' || f.severity === 'critical').length || 0;
                          return highCount > 0 ? (
                            <Chip label={highCount} size="small" color="error" sx={{ ml: 0.5, height: 20 }} />
                          ) : null;
                        })()}
                      </Box>
                    }
                    icon={<FindingsIcon fontSize="small" />} 
                    iconPosition="start" 
                  />
                  <Tab label="AI Analysis" />
                </Tabs>

                {nmapActiveTab === 0 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <Grid container spacing={2}>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="primary">
                                {data?.summary?.hosts_up || data?.hosts?.length || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Hosts Up
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="warning.main">
                                {data?.summary?.open_ports || data?.hosts?.reduce((acc: number, h: any) => acc + (h.ports?.filter((p: any) => p.state === "open").length || 0), 0) || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Open Ports
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="error.main">
                                {data?.findings?.filter((f: any) => f.severity === 'high' || f.severity === 'critical').length || 0}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                High-Risk Findings
                              </Typography>
                            </Card>
                          </Grid>
                          <Grid item xs={6} md={3}>
                            <Card sx={{ p: 2, textAlign: "center" }}>
                              <Typography variant="h4" color="success.main">
                                {Object.keys(data?.summary?.services_detected || {}).length || [...new Set(data?.hosts?.flatMap((h: any) => h.ports?.map((p: any) => p.service).filter(Boolean)) || [])].length}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Services
                              </Typography>
                            </Card>
                          </Grid>
                        </Grid>
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 1 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <NmapNetworkGraph
                          hosts={data?.hosts || []}
                          findings={data?.findings || []}
                          onHostClick={(host) => {
                            setSelectedHost(host);
                            setHostDrawerOpen(true);
                          }}
                          height={500}
                        />
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 2 && (
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>IP Address</TableCell>
                          <TableCell>Hostname</TableCell>
                          <TableCell>OS</TableCell>
                          <TableCell>State</TableCell>
                          <TableCell>Open Ports</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {(() => {
                          const data = getNmapSummary(nmapResult);
                          return (data?.hosts || []).map((host: any, idx: number) => (
                            <TableRow key={idx} hover sx={{ cursor: "pointer" }} onClick={() => { setSelectedHost(host); setHostDrawerOpen(true); }}>
                              <TableCell>
                                <Typography sx={{ fontFamily: "monospace" }}>{host.ip || host.address || "-"}</Typography>
                              </TableCell>
                              <TableCell>{host.hostname || host.hostnames?.[0] || "-"}</TableCell>
                              <TableCell>
                                <Tooltip title={host.os_guess || "Unknown"}>
                                  <Typography variant="body2" sx={{ maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                                    {host.os_guess ? (host.os_guess.length > 20 ? host.os_guess.substring(0, 20) + "..." : host.os_guess) : "-"}
                                  </Typography>
                                </Tooltip>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={host.state || host.status || "up"}
                                  size="small"
                                  color={host.state === "up" || host.status === "up" || !host.state ? "success" : "default"}
                                />
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={host.ports?.filter((p: any) => p.state === "open").length || host.open_ports || 0}
                                  size="small"
                                  color="primary"
                                  variant="outlined"
                                />
                              </TableCell>
                              <TableCell>
                                <IconButton size="small" onClick={(e) => { e.stopPropagation(); setSelectedHost(host); setHostDrawerOpen(true); }}>
                                  <ViewIcon fontSize="small" />
                                </IconButton>
                              </TableCell>
                            </TableRow>
                          ));
                        })()}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}

                {nmapActiveTab === 3 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      return (
                        <NmapFindingsTab
                          findings={data?.findings || []}
                          onHostClick={(hostIp) => {
                            const host = data?.hosts?.find((h: any) => h.ip === hostIp || h.address === hostIp);
                            if (host) {
                              setSelectedHost(host);
                              setHostDrawerOpen(true);
                            }
                          }}
                        />
                      );
                    })()}
                  </Box>
                )}

                {nmapActiveTab === 4 && (
                  <Box>
                    {(() => {
                      const data = getNmapSummary(nmapResult);
                      if (!data?.ai_analysis) {
                        return (
                          <Typography color="text.secondary">
                            No AI analysis available for this file.
                          </Typography>
                        );
                      }
                      return (
                        <ReactMarkdown
                          components={{
                            code: ({ className, children }) => (
                              <ChatCodeBlock className={className} theme={theme}>
                                {children}
                              </ChatCodeBlock>
                            ),
                          }}
                        >
                          {typeof data.ai_analysis === 'string' ? data.ai_analysis : JSON.stringify(data.ai_analysis, null, 2)}
                        </ReactMarkdown>
                      );
                    })()}
                  </Box>
                )}
              </Paper>
            )}

            {!nmapAnalyzing && !nmapResult && (
              <Paper sx={{ p: 4, textAlign: "center" }}>
                <UploadIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Upload an Nmap output file to analyze
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Supports XML, normal (.nmap), and grepable (.gnmap) formats
                </Typography>
              </Paper>
            )}
          </Grid>
        </Grid>
      )}

      {/* ================================================================ */}
      {/* NMAP COMMAND BUILDER MODE */}
      {/* ================================================================ */}
      {toolMode === "nmap-command" && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={5}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 3, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: "#f59e0b" }} />
                Nmap Command Builder
              </Typography>

              <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                <TextField
                  label="Target (IP/hostname/range)"
                  value={cmdGenTarget}
                  onChange={(e) => setCmdGenTarget(e.target.value)}
                  placeholder="e.g., 192.168.1.0/24, scanme.nmap.org"
                  fullWidth
                  size="small"
                />

                <FormControl fullWidth size="small">
                  <InputLabel>Scan Type</InputLabel>
                  <Select
                    value={cmdGenScanType}
                    onChange={(e) => setCmdGenScanType(e.target.value)}
                    label="Scan Type"
                  >
                    {nmapScanTypeOptions.map((opt) => (
                      <MenuItem key={opt.id} value={opt.id}>
                        <Box>
                          <Typography variant="body2">{opt.name}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {opt.flags || "(default)"} - {opt.description}
                          </Typography>
                        </Box>
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <TextField
                  label="Custom Ports (optional)"
                  value={cmdGenPorts}
                  onChange={(e) => setCmdGenPorts(e.target.value)}
                  placeholder="e.g., 22,80,443 or 1-1000"
                  fullWidth
                  size="small"
                  helperText="Leave empty for default port selection"
                />

                <FormControl fullWidth size="small">
                  <InputLabel>Output Format</InputLabel>
                  <Select
                    value={cmdGenOutputFormat}
                    onChange={(e) => setCmdGenOutputFormat(e.target.value as any)}
                    label="Output Format"
                  >
                    <MenuItem value="xml">XML (-oX) - Best for analysis</MenuItem>
                    <MenuItem value="normal">Normal (-oN) - Human readable</MenuItem>
                    <MenuItem value="grepable">Grepable (-oG) - Easy parsing</MenuItem>
                    <MenuItem value="all">All formats (-oA)</MenuItem>
                  </Select>
                </FormControl>

                <TextField
                  label="Output Filename (optional)"
                  value={cmdGenOutputFile}
                  onChange={(e) => setCmdGenOutputFile(e.target.value)}
                  placeholder="e.g., scan_results"
                  fullWidth
                  size="small"
                  helperText="Extension will be added automatically"
                />

                <TextField
                  label="Extra Flags (optional)"
                  value={cmdGenExtraFlags}
                  onChange={(e) => setCmdGenExtraFlags(e.target.value)}
                  placeholder="e.g., --reason -v"
                  fullWidth
                  size="small"
                  helperText="Additional nmap flags to include"
                />
              </Box>
            </Paper>

            {/* Scan Type Reference */}
            <Paper sx={{ p: 3, mt: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <LearnIcon sx={{ color: "#f59e0b" }} />
                Scan Type Reference
              </Typography>
              <List dense>
                {nmapScanTypeOptions.map((opt) => (
                  <ListItem 
                    key={opt.id}
                    onClick={() => setCmdGenScanType(opt.id)}
                    sx={{ 
                      cursor: "pointer",
                      borderRadius: 1,
                      bgcolor: cmdGenScanType === opt.id ? alpha("#f59e0b", 0.1) : "transparent",
                      "&:hover": { bgcolor: alpha("#f59e0b", 0.05) },
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {opt.name}
                          </Typography>
                          <Chip 
                            label={opt.flags || "default"} 
                            size="small" 
                            sx={{ 
                              fontFamily: "monospace",
                              bgcolor: alpha("#f59e0b", 0.2),
                            }}
                          />
                        </Box>
                      }
                      secondary={opt.description}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          <Grid item xs={12} md={7}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <TerminalIcon sx={{ color: "#f59e0b" }} />
                Generated Command
              </Typography>

              <Paper
                sx={{
                  p: 2,
                  bgcolor: "#1a1a2e",
                  borderRadius: 2,
                  fontFamily: "monospace",
                  position: "relative",
                }}
              >
                <Typography
                  sx={{
                    color: "#4ade80",
                    fontFamily: "monospace",
                    fontSize: "0.95rem",
                    wordBreak: "break-all",
                    whiteSpace: "pre-wrap",
                  }}
                >
                  $ {generateNmapCommand()}
                </Typography>
                <Tooltip title="Copy command">
                  <IconButton
                    onClick={handleCopyCommand}
                    sx={{
                      position: "absolute",
                      top: 8,
                      right: 8,
                      color: "#06b6d4",
                    }}
                  >
                    <CopyIcon />
                  </IconButton>
                </Tooltip>
              </Paper>

              <Button
                variant="contained"
                fullWidth
                startIcon={<CopyIcon />}
                onClick={handleCopyCommand}
                sx={{
                  mt: 2,
                  background: "linear-gradient(135deg, #f59e0b 0%, #d97706 100%)",
                }}
              >
                Copy Command to Clipboard
              </Button>

              {/* Common Examples */}
              <Box sx={{ mt: 4 }}>
                <Typography variant="subtitle1" sx={{ mb: 2, fontWeight: 600 }}>
                  Common Nmap Examples
                </Typography>
                <Grid container spacing={2}>
                  {[
                    { name: "Quick Host Discovery", cmd: "nmap -sn 192.168.1.0/24" },
                    { name: "Full Service Scan", cmd: "nmap -sV -sC -p- target" },
                    { name: "Stealth SYN Scan", cmd: "nmap -sS -T2 target" },
                    { name: "UDP Scan", cmd: "nmap -sU --top-ports 100 target" },
                    { name: "OS Detection", cmd: "nmap -O target" },
                    { name: "Vulnerability Scan", cmd: "nmap --script vuln target" },
                  ].map((ex, idx) => (
                    <Grid item xs={12} sm={6} key={idx}>
                      <Paper
                        onClick={() => {
                          navigator.clipboard.writeText(ex.cmd);
                          setSnackbar({ open: true, message: `Copied: ${ex.cmd}`, severity: "success" });
                        }}
                        sx={{
                          p: 2,
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha("#f59e0b", 0.05) },
                        }}
                      >
                        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 0.5 }}>
                          {ex.name}
                        </Typography>
                        <Typography
                          variant="body2"
                          sx={{ fontFamily: "monospace", color: "#f59e0b" }}
                        >
                          {ex.cmd}
                        </Typography>
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            </Paper>
          </Grid>
        </Grid>
      )}

      {/* ================================================================ */}
      {/* SAVED SCANS SECTION */}
      {/* ================================================================ */}
      <Paper sx={{ p: 3, mt: 3 }}>
        <Typography variant="h6" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
          <HistoryIcon sx={{ color: "#8b5cf6" }} />
          Saved Scans & Analysis
        </Typography>

        <Tabs
          value={nmapActiveTab}
          onChange={(_, v) => setNmapActiveTab(v)}
          sx={{ mb: 2, borderBottom: 1, borderColor: "divider" }}
        >
          <Tab 
            label={
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <RouteIcon sx={{ fontSize: 18 }} />
                Traceroute ({savedReports.length})
              </Box>
            } 
          />
          <Tab 
            label={
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <RadarIcon sx={{ fontSize: 18 }} />
                Nmap ({nmapSavedReports.length})
              </Box>
            } 
          />
        </Tabs>

        {/* Traceroute Reports */}
        {nmapActiveTab === 0 && (
          <Box>
            {loadingReports ? (
              <Box sx={{ display: "flex", justifyContent: "center", p: 3 }}>
                <CircularProgress size={24} />
              </Box>
            ) : savedReports.length === 0 ? (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <RouteIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                <Typography color="text.secondary">
                  No saved traceroute scans yet
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Run a traceroute scan to get started
                </Typography>
              </Box>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Title</TableCell>
                      <TableCell>Target</TableCell>
                      <TableCell>Risk Score</TableCell>
                      <TableCell>Findings</TableCell>
                      <TableCell>Date</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {savedReports.map((report) => (
                      <TableRow key={report.id} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 500 }}>
                            {report.title || "Untitled"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                            {report.filename || "-"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={`${report.risk_score}/10`}
                            size="small"
                            color={
                              report.risk_score >= 7 ? "error" :
                              report.risk_score >= 4 ? "warning" : "success"
                            }
                          />
                        </TableCell>
                        <TableCell>{report.total_findings}</TableCell>
                        <TableCell>
                          {new Date(report.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="View Report">
                            <IconButton
                              size="small"
                              onClick={async () => {
                                try {
                                  const detail = await apiClient.getTracerouteReport(report.id);
                                  setSelectedReport(detail);
                                  if (detail.report_data?.result) {
                                    setResult(detail.report_data.result as any);
                                  }
                                  setToolMode("traceroute");
                                } catch (err) {
                                  console.error("Failed to load report:", err);
                                }
                              }}
                            >
                              <ViewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              onClick={async () => {
                                try {
                                  await apiClient.deleteTracerouteReport(report.id);
                                  loadSavedReports();
                                  setSnackbar({ open: true, message: "Report deleted", severity: "success" });
                                } catch (err) {
                                  console.error("Failed to delete report:", err);
                                }
                              }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )}

        {/* Nmap Reports */}
        {nmapActiveTab === 1 && (
          <Box>
            {nmapSavedReports.length === 0 ? (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <RadarIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                <Typography color="text.secondary">
                  No saved Nmap scans yet
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Run an Nmap scan or upload a file for analysis
                </Typography>
              </Box>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Title</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Risk Level</TableCell>
                      <TableCell>Findings</TableCell>
                      <TableCell>Date</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {nmapSavedReports.map((report) => (
                      <TableRow key={report.id} hover>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 500 }}>
                            {report.title || "Untitled"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={report.analysis_type}
                            size="small"
                            sx={{ textTransform: "capitalize" }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={report.risk_level || "Unknown"}
                            size="small"
                            color={
                              report.risk_level === "critical" || report.risk_level === "high" ? "error" :
                              report.risk_level === "medium" ? "warning" : "success"
                            }
                          />
                        </TableCell>
                        <TableCell>{report.findings_count}</TableCell>
                        <TableCell>
                          {new Date(report.created_at).toLocaleDateString()}
                        </TableCell>
                        <TableCell align="right">
                          <Tooltip title="View Report">
                            <IconButton
                              size="small"
                              onClick={async () => {
                                try {
                                  const detail = await apiClient.getNetworkReport(report.id);
                                  // Transform to NmapAnalysisResult format
                                  setNmapResult({
                                    analysis_type: detail.analysis_type,
                                    total_files: 1,
                                    total_findings: detail.findings_data?.length || 0,
                                    analyses: [{
                                      analysis_type: detail.analysis_type,
                                      filename: detail.filename || "",
                                      summary: detail.summary_data || {},
                                      findings: detail.findings_data || [],
                                      ai_analysis: detail.ai_report,
                                    }],
                                    report_id: detail.id,
                                  });
                                  setToolMode("nmap-analyze");
                                  setNmapActiveTab(0);
                                } catch (err) {
                                  console.error("Failed to load report:", err);
                                }
                              }}
                            >
                              <ViewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete">
                            <IconButton
                              size="small"
                              onClick={async () => {
                                try {
                                  await apiClient.deleteNetworkReport(report.id);
                                  loadNmapReports();
                                  setSnackbar({ open: true, message: "Report deleted", severity: "success" });
                                } catch (err) {
                                  console.error("Failed to delete report:", err);
                                }
                              }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Box>
        )}

        <Box sx={{ mt: 2, display: "flex", justifyContent: "flex-end", gap: 1 }}>
          <Button
            variant="outlined"
            size="small"
            startIcon={<RefreshIcon />}
            onClick={() => {
              loadSavedReports();
              loadNmapReports();
            }}
          >
            Refresh
          </Button>
        </Box>
      </Paper>

      {/* Floating Chat Window */}
      {result && toolMode === "traceroute" && (
        <Paper
          elevation={8}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            left: chatMaximized ? { xs: 16, md: 280 } : "auto",
            width: showChat ? (chatMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 400 }) : "auto",
            maxWidth: chatMaximized ? "none" : 400,
            zIndex: 1200,
            borderRadius: 3,
            overflow: "hidden",
            transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Chat Header */}
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              p: 1.5,
              background: `linear-gradient(135deg, #ec4899 0%, #db2777 100%)`,
              color: "white",
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1,
                cursor: "pointer",
                flex: 1,
              }}
              onClick={() => setShowChat(!showChat)}
            >
              <ChatIcon />
              <Typography variant="subtitle1" fontWeight={600}>
                Traceroute Assistant
              </Typography>
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              {showChat && (
                <IconButton
                  size="small"
                  onClick={() => setChatMaximized(!chatMaximized)}
                  sx={{ color: "white" }}
                >
                  {chatMaximized ? <CloseFullscreenIcon fontSize="small" /> : <OpenInFullIcon fontSize="small" />}
                </IconButton>
              )}
              <IconButton
                size="small"
                onClick={() => setShowChat(!showChat)}
                sx={{ color: "white" }}
              >
                {showChat ? <ExpandMoreIcon /> : <ExpandLessIcon />}
              </IconButton>
            </Box>
          </Box>

          {/* Chat Content */}
          <Collapse in={showChat}>
            <Box sx={{ display: "flex", flexDirection: "column", height: chatMaximized ? "calc(66vh - 120px)" : 280 }}>
              {/* Messages */}
              <Box
                sx={{
                  flex: 1,
                  overflow: "auto",
                  p: 2,
                  bgcolor: alpha(theme.palette.background.paper, 0.98),
                }}
              >
                {chatMessages.length === 0 ? (
                  <Box sx={{ textAlign: "center", py: 3 }}>
                    <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Ask questions about the traceroute results, network path, or routing issues
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, justifyContent: "center" }}>
                      {chatSuggestions.map((suggestion, i) => (
                        <Chip
                          key={i}
                          label={suggestion}
                          size="small"
                          onClick={() => setChatInput(suggestion)}
                          sx={{ fontSize: "0.7rem", cursor: "pointer" }}
                        />
                      ))}
                    </Box>
                  </Box>
                ) : (
                  chatMessages.map((msg, i) => (
                    <Box
                      key={i}
                      sx={{
                        display: "flex",
                        gap: 1,
                        mb: 2,
                        flexDirection: msg.role === "user" ? "row-reverse" : "row",
                      }}
                    >
                      <Box
                        sx={{
                          width: 28,
                          height: 28,
                          borderRadius: "50%",
                          bgcolor: msg.role === "user" ? "#ec4899" : "secondary.main",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                        }}
                      >
                        {msg.role === "user" ? (
                          <PersonIcon sx={{ fontSize: 16, color: "white" }} />
                        ) : (
                          <SmartToyIcon sx={{ fontSize: 16, color: "white" }} />
                        )}
                      </Box>
                      <Paper
                        sx={{
                          p: 1.5,
                          maxWidth: "80%",
                          bgcolor: msg.role === "user" ? "#ec4899" : alpha(theme.palette.background.default, 0.8),
                          color: msg.role === "user" ? "white" : "text.primary",
                          borderRadius: 2,
                          "& p": { m: 0 },
                          "& p:not(:last-child)": { mb: 1 },
                          "& ul, & ol": { pl: 2, m: 0 },
                          "& li": { mb: 0.5 },
                        }}
                      >
                        <ReactMarkdown
                          components={{
                            code: ({ className, children }) => (
                              <ChatCodeBlock className={className} theme={theme}>
                                {children}
                              </ChatCodeBlock>
                            ),
                          }}
                        >
                          {msg.content}
                        </ReactMarkdown>
                      </Paper>
                    </Box>
                  ))
                )}
                {chatLoading && (
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CircularProgress size={20} />
                    <Typography variant="body2" color="text.secondary">
                      Analyzing...
                    </Typography>
                  </Box>
                )}
                <div ref={chatEndRef} />
              </Box>

              {/* Input */}
              <Box
                sx={{
                  p: 1.5,
                  borderTop: 1,
                  borderColor: "divider",
                  bgcolor: "background.paper",
                }}
              >
                <Box sx={{ display: "flex", gap: 1 }}>
                  <TextField
                    fullWidth
                    size="small"
                    placeholder="Ask about the route..."
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyPress={(e) => e.key === "Enter" && !e.shiftKey && handleSendChat()}
                    disabled={chatLoading}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        borderRadius: 2,
                      },
                    }}
                  />
                  <IconButton
                    color="primary"
                    onClick={handleSendChat}
                    disabled={!chatInput.trim() || chatLoading}
                  >
                    <SendIcon />
                  </IconButton>
                </Box>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}

      {/* Host Details Drawer */}
      <HostDetailsDrawer
        open={hostDrawerOpen}
        onClose={() => {
          setHostDrawerOpen(false);
          setSelectedHost(null);
        }}
        host={selectedHost}
        findings={(nmapResult ? getNmapSummary(nmapResult)?.findings || [] : []) as any}
      />

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default TracerouteAnalyzerPage;
