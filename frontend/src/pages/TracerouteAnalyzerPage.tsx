import React, { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
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
} from "@mui/icons-material";
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
} from "../api/client";
import NetworkTopologyGraph, { TopologyNode, TopologyLink } from "../components/NetworkTopologyGraph";

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
              <Typography variant="body2">{analysis.summary}</Typography>
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
                      primary={`${segment.segment} (Hops ${segment.hops})`}
                      secondary={segment.description}
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
                <strong>Overall Latency:</strong> {analysis.performance_analysis.overall_latency}
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
                        <ListItemText primary={bottleneck} />
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
                        <ListItemText primary={concern} />
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
                    <Typography variant="subtitle2">{obs.observation}</Typography>
                    <Chip
                      label={obs.severity}
                      size="small"
                      color={getSeverityColor(obs.severity) as any}
                    />
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    {obs.details}
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
                    <ListItemText primary={rec} />
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
              {analysis.raw_analysis}
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

  // Saved reports
  const [savedReports, setSavedReports] = useState<TracerouteSavedReport[]>([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [selectedReport, setSelectedReport] = useState<TracerouteReportDetail | null>(null);

  // Initialize
  useEffect(() => {
    loadStatus();
    loadSavedReports();
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
        setSnackbar({ open: true, message: "Traceroute complete!", severity: "success" });
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
        result: report.report_data.result,
        ai_analysis: report.ai_report || report.report_data.ai_analysis,
        report_id: report.id,
      });
      setActiveTab(0);
    } catch (err: any) {
      setSnackbar({ open: true, message: `Failed to load report: ${err.message}`, severity: "error" });
    }
  };

  const copyCommand = () => {
    const system = status?.platform || "windows";
    let cmd = "";
    
    if (system === "windows") {
      cmd = `tracert -h ${maxHops}${!resolveHostnames ? " -d" : ""} ${target}`;
    } else {
      cmd = `traceroute -m ${maxHops} -w ${timeout} -q ${queries}${!resolveHostnames ? " -n" : ""}${useIcmp ? " -I" : ""} ${target}`;
    }
    
    navigator.clipboard.writeText(cmd);
    setSnackbar({ open: true, message: "Command copied to clipboard", severity: "success" });
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

    // Add hop nodes
    result.result.hops.forEach((hop, index) => {
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

      // Add link from previous node
      const sourceId = index === 0 ? "source" : `hop-${result.result.hops[index - 1].hop_number}`;
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
  const exportResults = () => {
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
    
    result.result.hops.forEach(hop => {
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
    
    navigator.clipboard.writeText(text);
    setSnackbar({ open: true, message: "Results copied to clipboard", severity: "success" });
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
        <RouteIcon sx={{ fontSize: 40, color: "#ec4899" }} />
        <Box>
          <Typography variant="h4" sx={{ fontWeight: "bold" }}>
            Traceroute Visualization
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Visualize network paths and analyze routing performance
          </Typography>
        </Box>
        <Box sx={{ flex: 1 }} />
        <Tooltip title="Learn about Traceroute">
          <Button
            component={Link}
            to="/learn/traceroute"
            startIcon={<LearnIcon />}
            variant="outlined"
            size="small"
            sx={{ mr: 1 }}
          >
            Learn
          </Button>
        </Tooltip>
        <Chip
          icon={status?.available ? <CheckIcon /> : <ErrorIcon />}
          label={status?.available ? "Ready" : "Unavailable"}
          color={status?.available ? "success" : "error"}
        />
      </Box>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Main Content */}
      <Grid container spacing={3}>
        {/* Left Panel - Configuration */}
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Scan Configuration
            </Typography>

            {/* Target Input */}
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

                <FormControlLabel
                  control={
                    <Switch
                      checked={saveReport}
                      onChange={(e) => setSaveReport(e.target.checked)}
                      disabled={scanning}
                    />
                  }
                  label="Save Report"
                />

                {saveReport && (
                  <TextField
                    fullWidth
                    label="Report Title (optional)"
                    value={reportTitle}
                    onChange={(e) => setReportTitle(e.target.value)}
                    size="small"
                    disabled={scanning}
                    sx={{ mt: 1 }}
                  />
                )}
              </Box>
            </Collapse>

            {/* Action Buttons */}
            <Box sx={{ display: "flex", gap: 2 }}>
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
          {/* Live Progress */}
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

          {/* Results */}
          {result && (
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
                      {result.result.hops.map((hop) => (
                        <TableRow key={hop.hop_number}>
                          <TableCell>{hop.hop_number}</TableCell>
                          <TableCell>
                            {hop.is_timeout ? "*" : hop.ip_address || "-"}
                          </TableCell>
                          <TableCell>{hop.hostname || "-"}</TableCell>
                          <TableCell>
                            {hop.is_timeout
                              ? "*"
                              : hop.rtt_ms.map((r) => r.toFixed(1)).join(" / ")}
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
          {!result && !scanning && (
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
        </Grid>
      </Grid>

      {/* Floating Chat Window */}
      {showChat && result && (
        <Paper
          elevation={8}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            width: 400,
            height: 500,
            display: "flex",
            flexDirection: "column",
            zIndex: 1300,
            borderRadius: 2,
            overflow: "hidden",
          }}
        >
          {/* Chat Header */}
          <Box
            sx={{
              p: 2,
              bgcolor: "#ec4899",
              color: "white",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1">Ask about Traceroute</Typography>
            </Box>
            <IconButton size="small" onClick={() => setShowChat(false)} sx={{ color: "white" }}>
              <CloseIcon />
            </IconButton>
          </Box>

          {/* Chat Messages */}
          <Box
            sx={{
              flex: 1,
              overflow: "auto",
              p: 2,
              display: "flex",
              flexDirection: "column",
              gap: 1,
            }}
          >
            {chatMessages.length === 0 && (
              <Box sx={{ textAlign: "center", mt: 2 }}>
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
            )}
            {chatMessages.map((msg, i) => (
              <Box
                key={i}
                sx={{
                  alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "80%",
                }}
              >
                <Paper
                  sx={{
                    p: 1.5,
                    bgcolor: msg.role === "user" ? "#ec4899" : "grey.100",
                    color: msg.role === "user" ? "white" : "text.primary",
                    borderRadius: 2,
                  }}
                  elevation={1}
                >
                  <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                    {msg.content}
                  </Typography>
                </Paper>
              </Box>
            ))}
            {chatLoading && (
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <CircularProgress size={16} />
                <Typography variant="body2" color="text.secondary">
                  Thinking...
                </Typography>
              </Box>
            )}
          </Box>

          {/* Chat Input */}
          <Box sx={{ p: 2, borderTop: 1, borderColor: "divider" }}>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Ask about the route..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleSendChat()}
                disabled={chatLoading}
              />
              <IconButton onClick={handleSendChat} disabled={chatLoading || !chatInput.trim()}>
                <SendIcon />
              </IconButton>
            </Box>
          </Box>
        </Paper>
      )}

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
