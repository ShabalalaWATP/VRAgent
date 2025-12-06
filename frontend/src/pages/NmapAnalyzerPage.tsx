import React, { useState, useCallback, useEffect, useRef } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Alert,
  CircularProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Grid,
  Divider,
  IconButton,
  alpha,
  useTheme,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Breadcrumbs,
  Link as MuiLink,
  Tabs,
  Tab,
  TextField,
  Select,
  FormControl,
  InputLabel,
  FormHelperText,
  LinearProgress,
  Collapse,
} from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import { useDropzone } from "react-dropzone";
import RadarIcon from "@mui/icons-material/Radar";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import ComputerIcon from "@mui/icons-material/Computer";
import WarningIcon from "@mui/icons-material/Warning";
import SecurityIcon from "@mui/icons-material/Security";
import DownloadIcon from "@mui/icons-material/Download";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";
import HubIcon from "@mui/icons-material/Hub";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import ShieldIcon from "@mui/icons-material/Shield";
import BugReportIcon from "@mui/icons-material/BugReport";
import AssessmentIcon from "@mui/icons-material/Assessment";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import ChatIcon from "@mui/icons-material/Chat";
import SendIcon from "@mui/icons-material/Send";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import HistoryIcon from "@mui/icons-material/History";
import VisibilityIcon from "@mui/icons-material/Visibility";
import DeleteIcon from "@mui/icons-material/Delete";
import ReactMarkdown from "react-markdown";
import { apiClient, NmapAnalysisResult, NmapScanType, ChatMessage, SavedNetworkReport } from "../api/client";

// Structured Report Section Component (similar to PCAP)
const StructuredReportSection: React.FC<{ aiReport: any }> = ({ aiReport }) => {
  const theme = useTheme();

  if (!aiReport) return null;

  const report = aiReport.structured_report || aiReport;
  if (!report || typeof report === "string") {
    return (
      <Card sx={{ mt: 3, p: 3 }}>
        <Typography variant="h6" gutterBottom>
          AI Analysis
        </Typography>
        <Typography
          component="pre"
          sx={{
            whiteSpace: "pre-wrap",
            fontFamily: "monospace",
            fontSize: "0.85rem",
          }}
        >
          {typeof aiReport === "string" ? aiReport : JSON.stringify(aiReport, null, 2)}
        </Typography>
      </Card>
    );
  }

  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "#dc2626";
      case "high":
        return "#ea580c";
      case "medium":
        return "#ca8a04";
      case "low":
        return "#16a34a";
      default:
        return "#6b7280";
    }
  };

  return (
    <Box sx={{ mt: 4 }}>
      <Typography variant="h5" fontWeight={700} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <SecurityIcon color="primary" />
        AI Security Analysis Report
      </Typography>

      {/* Risk Overview */}
      {(report.risk_level || report.risk_score) && (
        <Card
          sx={{
            mb: 3,
            background: `linear-gradient(135deg, ${alpha(getRiskColor(report.risk_level), 0.15)} 0%, ${alpha(getRiskColor(report.risk_level), 0.05)} 100%)`,
            border: `1px solid ${alpha(getRiskColor(report.risk_level), 0.3)}`,
          }}
        >
          <CardContent>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 2 }}>
              <Box>
                <Typography variant="overline" color="text.secondary">
                  Overall Risk Level
                </Typography>
                <Typography variant="h4" fontWeight={700} sx={{ color: getRiskColor(report.risk_level) }}>
                  {report.risk_level?.toUpperCase() || "UNKNOWN"}
                </Typography>
              </Box>
              {report.risk_score !== undefined && (
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="overline" color="text.secondary">
                    Risk Score
                  </Typography>
                  <Typography variant="h3" fontWeight={800} sx={{ color: getRiskColor(report.risk_level) }}>
                    {report.risk_score}/100
                  </Typography>
                </Box>
              )}
            </Box>
          </CardContent>
        </Card>
      )}

      {/* Network Overview */}
      {report.network_overview && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <AssessmentIcon color="primary" />
              Network Overview
            </Typography>
            <Typography variant="body1">
              {typeof report.network_overview === 'string' 
                ? report.network_overview 
                : report.network_overview.assessment || JSON.stringify(report.network_overview)}
            </Typography>
            {typeof report.network_overview === 'object' && report.network_overview.attack_surface_rating && (
              <Chip 
                label={`Attack Surface: ${report.network_overview.attack_surface_rating}`} 
                size="small" 
                sx={{ mt: 1 }} 
              />
            )}
          </CardContent>
        </Card>
      )}

      {/* Key Findings */}
      {report.key_findings && report.key_findings.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BugReportIcon color="error" />
              Key Findings ({report.key_findings.length})
            </Typography>
            <Grid container spacing={2}>
              {report.key_findings.map((finding: any, idx: number) => (
                <Grid item xs={12} key={idx}>
                  <Paper
                    sx={{
                      p: 2,
                      borderLeft: `4px solid ${getRiskColor(finding.severity)}`,
                      bgcolor: alpha(getRiskColor(finding.severity), 0.05),
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                      <Chip
                        label={finding.severity?.toUpperCase()}
                        size="small"
                        sx={{
                          bgcolor: alpha(getRiskColor(finding.severity), 0.15),
                          color: getRiskColor(finding.severity),
                          fontWeight: 600,
                        }}
                      />
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle1" fontWeight={600}>
                          {finding.title || finding.finding}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {finding.description || finding.details}
                        </Typography>
                        {finding.affected_hosts && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                            Affected: {finding.affected_hosts.join(", ")}
                          </Typography>
                        )}
                        {finding.recommendation && (
                          <Alert severity="info" sx={{ mt: 1 }}>
                            {finding.recommendation}
                          </Alert>
                        )}
                      </Box>
                    </Box>
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Vulnerable Services */}
      {report.vulnerable_services && report.vulnerable_services.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <WarningIcon color="warning" />
              Vulnerable Services ({report.vulnerable_services.length})
            </Typography>
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Service</TableCell>
                    <TableCell>Host</TableCell>
                    <TableCell>Port</TableCell>
                    <TableCell>Issue</TableCell>
                    <TableCell>Risk</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {report.vulnerable_services.map((svc: any, idx: number) => (
                    <TableRow key={idx}>
                      <TableCell>{svc.service || svc.name}</TableCell>
                      <TableCell>{svc.host}</TableCell>
                      <TableCell>{svc.port}</TableCell>
                      <TableCell>{svc.issue || svc.vulnerability}</TableCell>
                      <TableCell>
                        <Chip
                          label={svc.risk || svc.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getRiskColor(svc.risk || svc.severity), 0.15),
                            color: getRiskColor(svc.risk || svc.severity),
                          }}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </CardContent>
        </Card>
      )}

      {/* High Risk Hosts */}
      {report.high_risk_hosts && report.high_risk_hosts.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ComputerIcon color="error" />
              High Risk Hosts ({report.high_risk_hosts.length})
            </Typography>
            <Grid container spacing={2}>
              {report.high_risk_hosts.map((host: any, idx: number) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.05), border: `1px solid ${alpha("#dc2626", 0.2)}` }}>
                    <Typography variant="subtitle1" fontWeight={600}>
                      {host.host || host.ip}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {host.reason || host.risks?.join(", ")}
                    </Typography>
                    {host.open_ports && (
                      <Box sx={{ mt: 1 }}>
                        <Typography variant="caption" color="text.secondary">
                          Open ports: {host.open_ports.join(", ")}
                        </Typography>
                      </Box>
                    )}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Attack Vectors */}
      {report.attack_vectors && report.attack_vectors.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ShieldIcon color="error" />
              Potential Attack Vectors
            </Typography>
            <Grid container spacing={2}>
              {report.attack_vectors.map((vector: any, idx: number) => (
                <Grid item xs={12} md={6} key={idx}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle2" fontWeight={600}>
                      {vector.name || vector.vector}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {vector.description}
                    </Typography>
                    {vector.mitre_id && (
                      <Chip label={vector.mitre_id} size="small" sx={{ mt: 1 }} variant="outlined" />
                    )}
                  </Paper>
                </Grid>
              ))}
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Recommendations */}
      {report.recommendations && report.recommendations.length > 0 && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LightbulbIcon color="success" />
              Recommendations
            </Typography>
            {report.recommendations.map((rec: any, idx: number) => (
              <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha("#16a34a", 0.05), border: `1px solid ${alpha("#16a34a", 0.2)}` }}>
                <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
                  <Chip
                    label={rec.priority || `#${idx + 1}`}
                    size="small"
                    sx={{ bgcolor: alpha("#16a34a", 0.15), color: "#16a34a" }}
                  />
                  <Box>
                    <Typography variant="subtitle2" fontWeight={600}>
                      {rec.title || rec.action}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {rec.description || rec.details}
                    </Typography>
                  </Box>
                </Box>
              </Paper>
            ))}
          </CardContent>
        </Card>
      )}
    </Box>
  );
};

const NmapAnalyzerPage: React.FC = () => {
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  const [files, setFiles] = useState<File[]>([]);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<NmapAnalysisResult | null>(null);
  const [reportId, setReportId] = useState<number | null>(null);
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);

  // Tab state
  const [activeTab, setActiveTab] = useState(0);

  // Scan state
  const [nmapInstalled, setNmapInstalled] = useState(false);
  const [scanTypes, setScanTypes] = useState<NmapScanType[]>([]);
  const [target, setTarget] = useState("");
  const [selectedScanType, setSelectedScanType] = useState("basic");
  const [customPorts, setCustomPorts] = useState("");
  const [scanTitle, setScanTitle] = useState("");
  const [targetValid, setTargetValid] = useState<boolean | null>(null);
  const [targetError, setTargetError] = useState<string | null>(null);

  // Saved reports state
  const [savedReports, setSavedReports] = useState<SavedNetworkReport[]>([]);
  const [loadingReports, setLoadingReports] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Handle sending chat message
  const handleSendMessage = async () => {
    if (!chatInput.trim() || !result || chatLoading) return;

    const userMessage: ChatMessage = { role: "user", content: chatInput.trim() };
    setChatMessages((prev) => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    setChatError(null);

    try {
      const firstAnalysis = result.analyses[0];
      const context = {
        summary: firstAnalysis?.summary,
        findings: firstAnalysis?.findings,
        hosts: firstAnalysis?.hosts,
        ai_analysis: firstAnalysis?.ai_analysis,
      };

      const response = await apiClient.chatAboutNetworkAnalysis(
        userMessage.content,
        chatMessages,
        context,
        "nmap"
      );

      if (response.error) {
        setChatError(response.error);
      } else {
        const assistantMessage: ChatMessage = { role: "assistant", content: response.response };
        setChatMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle Enter key in chat input
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Load saved reports
  const loadSavedReports = async () => {
    setLoadingReports(true);
    try {
      const reports = await apiClient.getNetworkReports("nmap");
      setSavedReports(reports);
    } catch (err) {
      console.error("Failed to load saved reports:", err);
    } finally {
      setLoadingReports(false);
    }
  };

  // Delete a saved report
  const handleDeleteReport = async (id: number) => {
    try {
      await apiClient.deleteNetworkReport(id);
      setSavedReports((prev) => prev.filter((r) => r.id !== id));
      setDeleteConfirmId(null);
    } catch (err) {
      console.error("Failed to delete report:", err);
    }
  };

  // Check nmap availability and load scan types
  useEffect(() => {
    const loadNmapInfo = async () => {
      try {
        const status = await apiClient.getNetworkStatus();
        setNmapInstalled(status.nmap_installed);
        if (status.nmap_installed) {
          const types = await apiClient.getNmapScanTypes();
          setScanTypes(types);
        }
      } catch (err) {
        console.error("Failed to load nmap info:", err);
      }
    };
    loadNmapInfo();
  }, []);

  // Load saved reports when switching to that tab
  useEffect(() => {
    if (activeTab === 2) {
      loadSavedReports();
    }
  }, [activeTab]);

  // Check for reportId in URL to load saved report
  useEffect(() => {
    const reportIdParam = searchParams.get("reportId");
    if (reportIdParam) {
      loadSavedReport(parseInt(reportIdParam, 10));
    }
  }, [searchParams]);

  const loadSavedReport = async (id: number) => {
    setAnalyzing(true);
    try {
      const report = await apiClient.getNetworkReport(id);
      // Convert saved report format to analysis result format
      setResult({
        analysis_type: "nmap",
        total_files: 1,
        total_findings: report.findings_data?.length || 0,
        analyses: [
          {
            analysis_type: "nmap",
            filename: report.filename || "",
            summary: report.summary_data as any,
            findings: report.findings_data || [],
            hosts: [],
            ai_analysis: report.ai_report,
          },
        ],
        report_id: id,
      });
      setReportId(id);
    } catch (err: any) {
      setError(err.message || "Failed to load report");
    } finally {
      setAnalyzing(false);
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const validFiles = acceptedFiles.filter((file) => {
      const ext = file.name.toLowerCase().split(".").pop();
      return ["xml", "nmap", "gnmap", "txt"].includes(ext || "");
    });
    setFiles((prev) => [...prev, ...validFiles]);
    setError(null);
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      "application/xml": [".xml"],
      "text/plain": [".nmap", ".gnmap", ".txt"],
    },
    multiple: true,
  });

  const removeFile = (index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAnalyze = async () => {
    if (files.length === 0) return;

    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await apiClient.analyzeNmap(files);
      setResult(response);
      setReportId(response.report_id || null);
    } catch (err: any) {
      setError(err.message || "Analysis failed");
    } finally {
      setAnalyzing(false);
    }
  };

  const handleExportClick = (event: React.MouseEvent<HTMLElement>) => {
    setExportAnchorEl(event.currentTarget);
  };

  const handleExportClose = () => {
    setExportAnchorEl(null);
  };

  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!reportId) return;
    try {
      const blob = await apiClient.exportNetworkReport(reportId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `nmap_report_${reportId}.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
    handleExportClose();
  };

  // Validate target when it changes
  const validateTarget = async (value: string) => {
    if (!value.trim()) {
      setTargetValid(null);
      setTargetError(null);
      return;
    }
    try {
      const result = await apiClient.validateNmapTarget(value);
      setTargetValid(result.valid);
      setTargetError(result.error || null);
    } catch (err: any) {
      setTargetValid(false);
      setTargetError(err.message || "Validation failed");
    }
  };

  // Debounce target validation
  useEffect(() => {
    const timer = setTimeout(() => {
      if (target) validateTarget(target);
    }, 500);
    return () => clearTimeout(timer);
  }, [target]);

  // Handle live scan
  const handleRunScan = async () => {
    if (!target.trim() || !targetValid) return;

    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      const response = await apiClient.runNmapScan({
        target: target.trim(),
        scan_type: selectedScanType,
        ports: customPorts.trim() || undefined,
        title: scanTitle.trim() || undefined,
      });
      setResult(response);
      setReportId(response.report_id || null);
    } catch (err: any) {
      setError(err.message || "Scan failed");
    } finally {
      setAnalyzing(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "#dc2626";
      case "high":
        return "#ea580c";
      case "medium":
        return "#ca8a04";
      case "low":
        return "#16a34a";
      default:
        return "#6b7280";
    }
  };

  return (
    <Box>
      {/* Breadcrumbs */}
      <Breadcrumbs separator={<NavigateNextIcon fontSize="small" />} sx={{ mb: 3 }}>
        <MuiLink component={Link} to="/network" color="inherit" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <HubIcon fontSize="small" />
          Network Analysis
        </MuiLink>
        <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <RadarIcon fontSize="small" />
          Nmap Analyzer
        </Typography>
      </Breadcrumbs>

      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <RadarIcon sx={{ fontSize: 32, color: "white" }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Nmap Scan Analyzer
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Run live scans or upload Nmap results for AI-powered security analysis
            </Typography>
          </Box>
        </Box>
        <Chip
          component={Link}
          to="/learn/nmap"
          icon={<LightbulbIcon sx={{ fontSize: 16 }} />}
          label="Learn Nmap Essentials →"
          clickable
          size="small"
          sx={{
            background: alpha("#8b5cf6", 0.1),
            border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
            color: "#a78bfa",
            fontWeight: 500,
            "&:hover": {
              background: alpha("#8b5cf6", 0.2),
            },
          }}
        />
      </Box>

      {/* Tabbed Interface */}
      {!result && (
        <Card sx={{ mb: 4 }}>
          <Tabs
            value={activeTab}
            onChange={(_, newValue) => setActiveTab(newValue)}
            sx={{
              borderBottom: 1,
              borderColor: "divider",
              px: 2,
              "& .MuiTab-root": {
                minHeight: 56,
                fontWeight: 600,
              },
            }}
          >
            <Tab
              icon={<GpsFixedIcon />}
              iconPosition="start"
              label="Run Live Scan"
              disabled={!nmapInstalled}
            />
            <Tab icon={<CloudUploadIcon />} iconPosition="start" label="Upload Files" />
            <Tab icon={<HistoryIcon />} iconPosition="start" label="Saved Reports" />
          </Tabs>

          <CardContent>
            {/* Tab 0: Run Live Scan */}
            {activeTab === 0 && (
              <Box>
                {!nmapInstalled ? (
                  <Alert severity="warning" sx={{ mb: 3 }}>
                    Nmap is not installed on the server. You can still upload existing Nmap scan files for analysis.
                  </Alert>
                ) : (
                  <>
                    <Grid container spacing={3}>
                      {/* Target Input */}
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          label="Target"
                          placeholder="192.168.1.1, 192.168.1.0/24, or example.com"
                          value={target}
                          onChange={(e) => setTarget(e.target.value)}
                          error={targetValid === false}
                          helperText={
                            targetError ||
                            "Enter an IP address, CIDR range (max /24), or hostname"
                          }
                          InputProps={{
                            startAdornment: (
                              <GpsFixedIcon sx={{ mr: 1, color: "text.secondary" }} />
                            ),
                            endAdornment: targetValid === true ? (
                              <Chip label="Valid" size="small" color="success" />
                            ) : null,
                          }}
                        />
                      </Grid>

                      {/* Scan Type */}
                      <Grid item xs={12}>
                        <FormControl fullWidth>
                          <InputLabel>Scan Type</InputLabel>
                          <Select
                            value={selectedScanType}
                            label="Scan Type"
                            onChange={(e) => setSelectedScanType(e.target.value)}
                            MenuProps={{
                              PaperProps: {
                                style: { maxHeight: 400 },
                              },
                            }}
                          >
                            {scanTypes.map((type) => (
                              <MenuItem
                                key={type.id}
                                value={type.id}
                                disabled={type.requires_root}
                              >
                                <Box sx={{ display: "flex", justifyContent: "space-between", width: "100%", alignItems: "center" }}>
                                  <Box>
                                    <Typography variant="body1" fontWeight={500}>{type.name}</Typography>
                                    <Typography variant="caption" color="text.secondary">
                                      {type.description}
                                    </Typography>
                                  </Box>
                                  <Chip
                                    label={type.estimated_time}
                                    size="small"
                                    variant="outlined"
                                    sx={{ ml: 2, minWidth: 80 }}
                                  />
                                </Box>
                              </MenuItem>
                            ))}
                          </Select>
                          <FormHelperText>
                            Ordered from fastest to most thorough. Estimated time: {scanTypes.find((t) => t.id === selectedScanType)?.estimated_time || "Unknown"}
                          </FormHelperText>
                        </FormControl>
                      </Grid>

                      {/* Custom Ports */}
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          label="Custom Ports (optional)"
                          placeholder="22,80,443 or 1-1000"
                          value={customPorts}
                          onChange={(e) => setCustomPorts(e.target.value)}
                          helperText="Override default ports. Leave empty to use scan type defaults."
                        />
                      </Grid>

                      {/* Report Title */}
                      <Grid item xs={12} md={6}>
                        <TextField
                          fullWidth
                          label="Report Title (optional)"
                          placeholder="My Security Scan"
                          value={scanTitle}
                          onChange={(e) => setScanTitle(e.target.value)}
                          helperText="Custom title for the saved report"
                        />
                      </Grid>
                    </Grid>

                    {/* Scan Type Info */}
                    {selectedScanType && (
                      <Alert
                        severity="info"
                        sx={{ mt: 3 }}
                        icon={<RadarIcon />}
                      >
                        <Typography variant="body2">
                          <strong>
                            {scanTypes.find((t) => t.id === selectedScanType)?.name}:
                          </strong>{" "}
                          {scanTypes.find((t) => t.id === selectedScanType)?.description}
                          <br />
                          <Typography component="span" variant="caption" color="text.secondary">
                            Estimated time: <strong>{scanTypes.find((t) => t.id === selectedScanType)?.estimated_time}</strong> per host
                            {" • "}
                            Max timeout: {Math.round((scanTypes.find((t) => t.id === selectedScanType)?.timeout || 0) / 60)} min
                          </Typography>
                        </Typography>
                      </Alert>
                    )}

                    {/* Run Scan Button */}
                    <Button
                      variant="contained"
                      size="large"
                      onClick={handleRunScan}
                      disabled={analyzing || !targetValid || !target.trim()}
                      sx={{
                        mt: 3,
                        py: 1.5,
                        px: 4,
                        background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                        "&:hover": {
                          background: `linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)`,
                        },
                      }}
                      startIcon={
                        analyzing ? <CircularProgress size={20} color="inherit" /> : <PlayArrowIcon />
                      }
                    >
                      {analyzing ? "Scanning..." : "Start Scan"}
                    </Button>
                  </>
                )}
              </Box>
            )}

            {/* Tab 1: Upload Files */}
            {activeTab === 1 && (
              <Box>
                <Box
                  {...getRootProps()}
                  sx={{
                    p: 4,
                    border: `2px dashed ${isDragActive ? theme.palette.primary.main : alpha(theme.palette.divider, 0.5)}`,
                    borderRadius: 2,
                    bgcolor: isDragActive ? alpha(theme.palette.primary.main, 0.05) : "transparent",
                    textAlign: "center",
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    "&:hover": {
                      borderColor: theme.palette.primary.main,
                      bgcolor: alpha(theme.palette.primary.main, 0.02),
                    },
                  }}
                >
                  <input {...getInputProps()} />
                  <CloudUploadIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
                  <Typography variant="h6" gutterBottom>
                    {isDragActive ? "Drop files here..." : "Drag & drop Nmap files here"}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    or click to browse • Supports .xml, .nmap, .gnmap, .txt
                  </Typography>
                </Box>

                {files.length > 0 && (
                  <Box sx={{ mt: 3 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Selected Files ({files.length})
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                      {files.map((file, idx) => (
                        <Chip
                          key={idx}
                          label={file.name}
                          onDelete={() => removeFile(idx)}
                          variant="outlined"
                        />
                      ))}
                    </Box>
                    <Button
                      variant="contained"
                      onClick={handleAnalyze}
                      disabled={analyzing}
                      sx={{
                        mt: 3,
                        background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                        "&:hover": {
                          background: `linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)`,
                        },
                      }}
                      startIcon={analyzing ? <CircularProgress size={20} /> : <RadarIcon />}
                    >
                      {analyzing ? "Analyzing..." : "Analyze Scans"}
                    </Button>
                  </Box>
                )}

                <Alert severity="info" sx={{ mt: 3 }}>
                  <Typography variant="body2">
                    <strong>Tip:</strong> Export Nmap scans with XML output for best results:
                    <br />
                    <code>nmap -sV -sC -oX scan_result.xml target</code>
                  </Typography>
                </Alert>
              </Box>
            )}

            {/* Tab 2: Saved Reports */}
            {activeTab === 2 && (
              <Box>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
                  <Typography variant="h6" fontWeight={600}>
                    Saved Nmap Reports
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={loadSavedReports}
                    startIcon={loadingReports ? <CircularProgress size={16} /> : <HistoryIcon />}
                    disabled={loadingReports}
                  >
                    Refresh
                  </Button>
                </Box>

                {loadingReports ? (
                  <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
                    <CircularProgress />
                  </Box>
                ) : savedReports.length === 0 ? (
                  <Box sx={{ textAlign: "center", py: 6 }}>
                    <HistoryIcon sx={{ fontSize: 64, color: "text.secondary", mb: 2 }} />
                    <Typography variant="h6" color="text.secondary" gutterBottom>
                      No Saved Reports
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Run a scan or upload files to create reports
                    </Typography>
                  </Box>
                ) : (
                  <TableContainer component={Paper} variant="outlined">
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell>Title</TableCell>
                          <TableCell>Date</TableCell>
                          <TableCell>Risk Level</TableCell>
                          <TableCell align="center">Findings</TableCell>
                          <TableCell align="right">Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {savedReports.map((report) => (
                          <TableRow
                            key={report.id}
                            hover
                            sx={{ "&:last-child td, &:last-child th": { border: 0 } }}
                          >
                            <TableCell>
                              <Box>
                                <Typography variant="body2" fontWeight={600}>
                                  {report.title}
                                </Typography>
                                {report.filename && (
                                  <Typography variant="caption" color="text.secondary">
                                    {report.filename}
                                  </Typography>
                                )}
                              </Box>
                            </TableCell>
                            <TableCell>
                              <Typography variant="body2">
                                {new Date(report.created_at).toLocaleDateString()}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {new Date(report.created_at).toLocaleTimeString()}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              {report.risk_level ? (
                                <Chip
                                  label={report.risk_level.toUpperCase()}
                                  size="small"
                                  sx={{
                                    bgcolor: alpha(getSeverityColor(report.risk_level), 0.15),
                                    color: getSeverityColor(report.risk_level),
                                    fontWeight: 600,
                                  }}
                                />
                              ) : (
                                <Typography variant="body2" color="text.secondary">
                                  —
                                </Typography>
                              )}
                            </TableCell>
                            <TableCell align="center">
                              <Typography variant="body2" fontWeight={500}>
                                {report.findings_count}
                              </Typography>
                            </TableCell>
                            <TableCell align="right">
                              <Box sx={{ display: "flex", gap: 1, justifyContent: "flex-end" }}>
                                <Tooltip title="View Report">
                                  <IconButton
                                    size="small"
                                    color="primary"
                                    onClick={() => loadSavedReport(report.id)}
                                  >
                                    <VisibilityIcon fontSize="small" />
                                  </IconButton>
                                </Tooltip>
                                {deleteConfirmId === report.id ? (
                                  <>
                                    <Button
                                      size="small"
                                      color="error"
                                      variant="contained"
                                      onClick={() => handleDeleteReport(report.id)}
                                    >
                                      Confirm
                                    </Button>
                                    <Button
                                      size="small"
                                      onClick={() => setDeleteConfirmId(null)}
                                    >
                                      Cancel
                                    </Button>
                                  </>
                                ) : (
                                  <Tooltip title="Delete Report">
                                    <IconButton
                                      size="small"
                                      color="error"
                                      onClick={() => setDeleteConfirmId(report.id)}
                                    >
                                      <DeleteIcon fontSize="small" />
                                    </IconButton>
                                  </Tooltip>
                                )}
                              </Box>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {analyzing && !result && (
        <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 6 }}>
          <CircularProgress size={60} sx={{ mb: 2 }} />
          <Typography variant="h6">
            {activeTab === 0 ? "Running Nmap scan..." : "Analyzing Nmap scans..."}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {activeTab === 0
              ? `Scanning ${target} - this may take several minutes depending on scan type`
              : "This may take a moment depending on the scan size"}
          </Typography>
          {activeTab === 0 && (
            <Box sx={{ width: "100%", maxWidth: 400, mt: 3 }}>
              <LinearProgress color="secondary" />
            </Box>
          )}
        </Box>
      )}

      {/* Results */}
      {result && (
        <Box>
          {/* Summary Card */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Typography variant="h6" fontWeight={600}>
                  Analysis Summary
                </Typography>
                <Box sx={{ display: "flex", gap: 1 }}>
                  {reportId && (
                    <>
                      <Button
                        startIcon={<DownloadIcon />}
                        onClick={handleExportClick}
                        variant="outlined"
                      >
                        Export
                      </Button>
                      <Menu
                        anchorEl={exportAnchorEl}
                        open={Boolean(exportAnchorEl)}
                        onClose={handleExportClose}
                      >
                        <MenuItem onClick={() => handleExport("markdown")}>
                          <ListItemIcon>
                            <DescriptionIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>Markdown (.md)</ListItemText>
                        </MenuItem>
                        <MenuItem onClick={() => handleExport("pdf")}>
                          <ListItemIcon>
                            <PictureAsPdfIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>PDF (.pdf)</ListItemText>
                        </MenuItem>
                        <MenuItem onClick={() => handleExport("docx")}>
                          <ListItemIcon>
                            <ArticleIcon fontSize="small" />
                          </ListItemIcon>
                          <ListItemText>Word (.docx)</ListItemText>
                        </MenuItem>
                      </Menu>
                    </>
                  )}
                  <Button
                    onClick={() => {
                      setResult(null);
                      setFiles([]);
                      setReportId(null);
                    }}
                  >
                    New Analysis
                  </Button>
                </Box>
              </Box>

              <Grid container spacing={3}>
                <Grid item xs={6} sm={3}>
                  <Typography variant="overline" color="text.secondary">
                    Files Analyzed
                  </Typography>
                  <Typography variant="h4" fontWeight={700}>
                    {result.total_files}
                  </Typography>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Typography variant="overline" color="text.secondary">
                    Total Findings
                  </Typography>
                  <Typography variant="h4" fontWeight={700} color="warning.main">
                    {result.total_findings}
                  </Typography>
                </Grid>
                {result.analyses[0]?.summary && (
                  <>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="overline" color="text.secondary">
                        Hosts Discovered
                      </Typography>
                      <Typography variant="h4" fontWeight={700}>
                        {result.analyses[0].summary.total_hosts || 0}
                      </Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="overline" color="text.secondary">
                        Open Ports
                      </Typography>
                      <Typography variant="h4" fontWeight={700} color="error.main">
                        {result.analyses[0].summary.open_ports || 0}
                      </Typography>
                    </Grid>
                  </>
                )}
              </Grid>
            </CardContent>
          </Card>

          {/* Findings Table */}
          {result.total_findings > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h6" fontWeight={600} gutterBottom>
                  Security Findings
                </Typography>
                <TableContainer>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Severity</TableCell>
                        <TableCell>Category</TableCell>
                        <TableCell>Title</TableCell>
                        <TableCell>Host</TableCell>
                        <TableCell>Port/Service</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {result.analyses.flatMap((analysis) =>
                        (analysis.findings || []).map((finding: any, idx: number) => (
                          <TableRow key={`${analysis.filename}-${idx}`}>
                            <TableCell>
                              <Chip
                                label={finding.severity}
                                size="small"
                                sx={{
                                  bgcolor: alpha(getSeverityColor(finding.severity), 0.15),
                                  color: getSeverityColor(finding.severity),
                                  fontWeight: 600,
                                }}
                              />
                            </TableCell>
                            <TableCell>{finding.category}</TableCell>
                            <TableCell>
                              <Typography variant="body2" fontWeight={500}>
                                {finding.title}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                {finding.description?.substring(0, 100)}...
                              </Typography>
                            </TableCell>
                            <TableCell>{finding.host}</TableCell>
                            <TableCell>
                              {finding.port && `${finding.port}`}
                              {finding.service && ` (${finding.service})`}
                            </TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </Card>
          )}

          {/* Hosts Discovery */}
          {result.analyses.some((a) => a.hosts && a.hosts.length > 0) && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h6" fontWeight={600} gutterBottom>
                  Discovered Hosts
                </Typography>
                {result.analyses.map((analysis) =>
                  analysis.hosts?.map((host: any, idx: number) => (
                    <Accordion key={`${analysis.filename}-host-${idx}`}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                          <ComputerIcon color="primary" />
                          <Box>
                            <Typography fontWeight={600}>{host.ip}</Typography>
                            {host.hostname && (
                              <Typography variant="caption" color="text.secondary">
                                {host.hostname}
                              </Typography>
                            )}
                          </Box>
                          <Chip
                            label={host.status || "up"}
                            size="small"
                            color={host.status === "up" ? "success" : "default"}
                          />
                          <Chip
                            label={`${host.ports?.length || 0} open ports`}
                            size="small"
                            variant="outlined"
                          />
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {host.ports && host.ports.length > 0 && (
                          <TableContainer>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Port</TableCell>
                                  <TableCell>State</TableCell>
                                  <TableCell>Service</TableCell>
                                  <TableCell>Version</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {host.ports.map((port: any, pidx: number) => (
                                  <TableRow key={pidx}>
                                    <TableCell>
                                      {port.port}/{port.protocol || "tcp"}
                                    </TableCell>
                                    <TableCell>
                                      <Chip
                                        label={port.state || "open"}
                                        size="small"
                                        color={port.state === "open" ? "success" : "warning"}
                                      />
                                    </TableCell>
                                    <TableCell>{port.service || "-"}</TableCell>
                                    <TableCell>{port.version || "-"}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  ))
                )}
              </CardContent>
            </Card>
          )}

          {/* AI Analysis */}
          {result.analyses[0]?.ai_analysis && (
            <StructuredReportSection aiReport={result.analyses[0].ai_analysis} />
          )}
        </Box>
      )}

      {/* Chat Window - Only visible when results are available */}
      {result && (
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            right: 24,
            width: chatOpen ? 450 : 200,
            maxHeight: chatOpen ? "60vh" : "auto",
            zIndex: 1200,
            borderRadius: "12px 12px 0 0",
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
            overflow: "hidden",
            transition: "all 0.3s ease",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => setChatOpen(!chatOpen)}
            sx={{
              p: 2,
              bgcolor: "#7c3aed",
              color: "white",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { bgcolor: "#6d28d9" },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask About This Scan
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: "white" }}>
              {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
            </IconButton>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: "calc(60vh - 140px)",
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
                  <Typography variant="body1" color="text.secondary" gutterBottom>
                    Ask me anything about this Nmap scan!
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    I can help explain findings, suggest remediation steps, or analyze specific hosts and services.
                  </Typography>
                  <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center" }}>
                    {[
                      "What are the main security risks?",
                      "Explain the open ports found",
                      "What should I prioritize fixing?",
                      "Are there any critical vulnerabilities?",
                    ].map((suggestion) => (
                      <Chip
                        key={suggestion}
                        label={suggestion}
                        size="small"
                        onClick={() => {
                          setChatInput(suggestion);
                        }}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha("#7c3aed", 0.1) } }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat messages */}
              {chatMessages.map((msg, idx) => (
                <Box
                  key={idx}
                  sx={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box sx={{ display: "flex", gap: 1, maxWidth: "85%" }}>
                    {msg.role === "assistant" && (
                      <Box
                        sx={{
                          width: 32,
                          height: 32,
                          borderRadius: "50%",
                          bgcolor: "#7c3aed",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                        }}
                      >
                        <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                      </Box>
                    )}
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? "#7c3aed" : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& code": {
                          bgcolor: alpha(msg.role === "user" ? "#fff" : "#7c3aed", 0.2),
                          px: 0.5,
                          borderRadius: 0.5,
                          fontFamily: "monospace",
                          fontSize: "0.85em",
                        },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                      }}
                    >
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </Paper>
                    {msg.role === "user" && (
                      <Box
                        sx={{
                          width: 32,
                          height: 32,
                          borderRadius: "50%",
                          bgcolor: theme.palette.grey[400],
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          flexShrink: 0,
                        }}
                      >
                        <PersonIcon sx={{ fontSize: 18, color: "white" }} />
                      </Box>
                    )}
                  </Box>
                </Box>
              ))}

              {/* Loading indicator */}
              {chatLoading && (
                <Box sx={{ display: "flex", justifyContent: "flex-start", mb: 2 }}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: "#7c3aed",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                    </Box>
                    <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <CircularProgress size={8} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.2s" }} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.4s" }} />
                      </Box>
                    </Paper>
                  </Box>
                </Box>
              )}

              {/* Error message */}
              {chatError && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setChatError(null)}>
                  {chatError}
                </Alert>
              )}

              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
              }}
            >
              <Box sx={{ display: "flex", gap: 1 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Ask about the scan results..."
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={handleChatKeyDown}
                  disabled={chatLoading}
                  multiline
                  maxRows={3}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      borderRadius: 2,
                    },
                  }}
                />
                <IconButton
                  color="primary"
                  onClick={handleSendMessage}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: "#7c3aed",
                    color: "white",
                    "&:hover": { bgcolor: "#6d28d9" },
                    "&:disabled": { bgcolor: theme.palette.action.disabledBackground },
                  }}
                >
                  <SendIcon />
                </IconButton>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}
    </Box>
  );
};

export default NmapAnalyzerPage;
