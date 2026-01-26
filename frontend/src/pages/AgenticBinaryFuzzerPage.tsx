import { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  TextField,
  Grid,
  Chip,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  FormControlLabel,
  Switch,
  Slider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
  CircularProgress,
} from '@mui/material';
import {
  Upload as UploadIcon,
  PlayArrow as PlayIcon,
  Pause as PauseIcon,
  Stop as StopIcon,
  BugReport as BugIcon,
  Security as SecurityIcon,
  Memory as MemoryIcon,
  Timeline as TimelineIcon,
  Code as CodeIcon,
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  Refresh as RefreshIcon,
  Analytics as AnalyticsIcon,
  Psychology as AIIcon,
  Terminal as TerminalIcon,
  Download as DownloadIcon,
  Description as ReportIcon,
  Delete as DeleteIcon,
  OpenInNew as OpenIcon,
  PictureAsPdf as PdfIcon,
  Article as WordIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';

// Simple API helper for this page
const API_URL = import.meta.env.VITE_API_URL || '/api';
const getAuthHeaders = () => {
  const token = localStorage.getItem('vragent_access_token');
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  return headers;
};

const api = {
  get: async (url: string) => {
    const resp = await fetch(`${API_URL}${url}`, { headers: getAuthHeaders() });
    if (!resp.ok) throw { response: { data: { detail: await resp.text() } } };
    return { data: await resp.json() };
  },
  post: async (url: string, body?: FormData | object, options?: { headers?: Record<string, string>; params?: Record<string, any> }) => {
    let fullUrl = `${API_URL}${url}`;
    if (options?.params) {
      const searchParams = new URLSearchParams();
      for (const [key, value] of Object.entries(options.params)) {
        if (value !== undefined) searchParams.append(key, String(value));
      }
      fullUrl += `?${searchParams.toString()}`;
    }
    const headers: Record<string, string> = { ...getAuthHeaders() };
    const isFormData = body instanceof FormData;
    if (!isFormData && body) headers['Content-Type'] = 'application/json';
    const resp = await fetch(fullUrl, {
      method: 'POST',
      headers,
      body: isFormData ? body : body ? JSON.stringify(body) : undefined,
    });
    if (!resp.ok) throw { response: { data: { detail: await resp.text() } } };
    const text = await resp.text();
    return { data: text ? JSON.parse(text) : {} };
  },
};

interface Campaign {
  campaign_id: string;
  status: string;
  binary_name?: string;
  elapsed_time?: string;
  total_executions: number;
  coverage_percentage: number;
  unique_crashes: number;
  exploitable_crashes: number;
  corpus_size: number;
  executions_per_second: number;
  current_strategy?: string;
  decisions_made: number;
}

interface QuickAnalysis {
  binary_name: string;
  file_type: string;
  architecture: string;
  size_bytes: number;
  hash: string;
  protections: Record<string, boolean>;
  attack_surface_score: number;
  recommended_strategy: string;
  estimated_difficulty: string;
  dangerous_functions: string[];
  input_handlers: string[];
  interesting_strings: string[];
  ai_recommendation: string;
}

interface CrashInfo {
  crash_id: string;
  crash_type: string;
  exploitability: string;
  confidence: number;
}

interface Decision {
  decision_id: string;
  type: string;
  reasoning: string;
  timestamp: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
}

interface EnvironmentStatus {
  afl_available: boolean;
  afl_version: string | null;
  mock_mode: boolean;
  warning: string | null;
  ai_enabled: boolean;
  decision_interval_seconds: number;
  estimated_ai_calls_per_hour: number;
}

interface ReportListItem {
  id: number;
  campaign_id: string;
  binary_name: string;
  status: string;
  risk_rating: string | null;
  final_coverage: number | null;
  unique_crashes: number;
  exploitable_crashes: number;
  duration_seconds: number | null;
  created_at: string;
}

interface ReportDetail {
  id: number;
  campaign_id: string;
  binary_name: string;
  binary_hash: string | null;
  binary_type: string | null;
  architecture: string | null;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  total_executions: number;
  executions_per_second: number | null;
  final_coverage: number | null;
  unique_crashes: number;
  exploitable_crashes: number;
  total_decisions: number;
  executive_summary: string | null;
  findings_summary: string | null;
  recommendations: string | null;
  report_data: {
    risk_rating?: string;
    key_findings?: string[];
    strategy_effectiveness?: Record<string, any>;
  } | null;
  decisions: Array<{
    decision_id: string;
    timestamp: string;
    decision_type: string;
    reasoning: string;
  }> | null;
  crashes: Array<{
    crash_id: string;
    crash_type: string;
    exploitability: string;
    confidence: number;
    impact: string | null;
    recommendation: string | null;
  }> | null;
  created_at: string;
}

export default function AgenticBinaryFuzzerPage() {
  const [activeTab, setActiveTab] = useState(0);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analysis, setAnalysis] = useState<QuickAnalysis | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [activeCampaign, setActiveCampaign] = useState<Campaign | null>(null);
  const [crashes, setCrashes] = useState<CrashInfo[]>([]);
  const [decisions, setDecisions] = useState<Decision[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [configDialog, setConfigDialog] = useState(false);
  const [envStatus, setEnvStatus] = useState<EnvironmentStatus | null>(null);

  // Reports state
  const [reports, setReports] = useState<ReportListItem[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null);
  const [reportDialogOpen, setReportDialogOpen] = useState(false);
  const [loadingReport, setLoadingReport] = useState(false);

  // Campaign configuration
  const [config, setConfig] = useState({
    maxDurationHours: 2,
    maxEngines: 4,
    strategy: 'coverage_guided',
    enableAI: true,
    stopOnExploitable: false,
    targetCoverage: 0,
  });

  // Duration presets for easy selection
  const durationPresets = [
    { label: 'Quick', hours: 0.5, description: 'Smoke test (30 min)', aiCalls: '~6' },
    { label: 'Standard', hours: 2, description: 'Most use cases', aiCalls: '~24' },
    { label: 'Thorough', hours: 8, description: 'Security review', aiCalls: '~96' },
    { label: 'Deep', hours: 24, description: 'Critical targets', aiCalls: '~288' },
  ];

  // Load campaigns, reports, and environment status on mount
  useEffect(() => {
    loadCampaigns();
    loadReports();
    checkEnvironment();
  }, []);

  const checkEnvironment = async () => {
    try {
      const response = await api.get('/agentic-binary/environment');
      setEnvStatus(response.data);
    } catch (err) {
      console.error('Failed to check environment:', err);
    }
  };

  const loadReports = async () => {
    try {
      const response = await api.get('/agentic-binary/reports');
      setReports(response.data);
    } catch (err) {
      console.error('Failed to load reports:', err);
    }
  };

  const viewReport = async (campaignId: string) => {
    setLoadingReport(true);
    try {
      const response = await api.get(`/agentic-binary/reports/${campaignId}`);
      setSelectedReport(response.data);
      setReportDialogOpen(true);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load report');
    } finally {
      setLoadingReport(false);
    }
  };

  const exportReport = async (campaignId: string, format: 'md' | 'pdf' | 'docx') => {
    try {
      const response = await fetch(`${API_URL}/agentic-binary/reports/${campaignId}/export/${format}`, {
        headers: getAuthHeaders(),
      });
      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fuzzing_report_${campaignId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      setError(err.message || 'Failed to export report');
    }
  };

  const deleteReport = async (campaignId: string) => {
    if (!confirm('Are you sure you want to delete this report?')) return;
    try {
      await fetch(`${API_URL}/agentic-binary/reports/${campaignId}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
      loadReports();
    } catch (err: any) {
      setError(err.message || 'Failed to delete report');
    }
  };

  const formatDuration = (seconds: number | null): string => {
    if (!seconds) return 'N/A';
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    if (hours > 0) return `${hours}h ${minutes}m`;
    return `${minutes}m`;
  };

  const getRiskColor = (risk: string | null) => {
    switch (risk?.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  // Poll active campaign status
  useEffect(() => {
    if (activeCampaign && activeCampaign.status === 'running') {
      const interval = setInterval(() => {
        refreshCampaignStatus(activeCampaign.campaign_id);
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [activeCampaign]);

  const loadCampaigns = async () => {
    try {
      const response = await api.get('/agentic-binary/campaigns');
      setCampaigns(response.data);
    } catch (err) {
      console.error('Failed to load campaigns:', err);
    }
  };

  const refreshCampaignStatus = async (campaignId: string) => {
    try {
      const response = await api.get(`/agentic-binary/campaigns/${campaignId}`);
      setActiveCampaign(response.data);

      // Also refresh crashes and decisions
      const [crashesRes, decisionsRes] = await Promise.all([
        api.get(`/agentic-binary/campaigns/${campaignId}/crashes`),
        api.get(`/agentic-binary/campaigns/${campaignId}/decisions`),
      ]);
      setCrashes(crashesRes.data.slice(-20));
      setDecisions(decisionsRes.data.slice(-20));
    } catch (err) {
      console.error('Failed to refresh campaign:', err);
    }
  };

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
      setLoading(true);

      try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await api.post('/agentic-binary/analyze/quick', formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        });
        setAnalysis(response.data);
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Analysis failed');
      } finally {
        setLoading(false);
      }
    }
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.exe', '.elf', '.bin', '.so', '.dll'],
      'application/x-executable': [],
      'application/x-sharedlib': [],
    },
    maxFiles: 1,
  });

  const startCampaign = async () => {
    if (!selectedFile) return;

    setLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await api.post('/agentic-binary/campaigns', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        params: {
          max_duration_hours: config.maxDurationHours,
          max_engines: config.maxEngines,
          strategy: config.strategy,
          enable_ai: config.enableAI,
          stop_on_exploitable: config.stopOnExploitable,
        },
      });

      const campaignId = response.data.campaign_id;
      await refreshCampaignStatus(campaignId);
      loadCampaigns();
      setActiveTab(1);
      setConfigDialog(false);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to start campaign');
    } finally {
      setLoading(false);
    }
  };

  const pauseCampaign = async () => {
    if (!activeCampaign) return;
    try {
      await api.post(`/agentic-binary/campaigns/${activeCampaign.campaign_id}/pause`);
      refreshCampaignStatus(activeCampaign.campaign_id);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to pause campaign');
    }
  };

  const resumeCampaign = async () => {
    if (!activeCampaign) return;
    try {
      await api.post(`/agentic-binary/campaigns/${activeCampaign.campaign_id}/resume`);
      refreshCampaignStatus(activeCampaign.campaign_id);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to resume campaign');
    }
  };

  const stopCampaign = async () => {
    if (!activeCampaign) return;
    try {
      await api.post(`/agentic-binary/campaigns/${activeCampaign.campaign_id}/stop`);
      refreshCampaignStatus(activeCampaign.campaign_id);
      // Reload reports after a delay to allow backend to generate report
      setTimeout(() => {
        loadReports();
      }, 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to stop campaign');
    }
  };

  const getExploitabilityColor = (exploitability: string) => {
    switch (exploitability.toLowerCase()) {
      case 'exploitable':
        return 'error';
      case 'probably_exploitable':
        return 'warning';
      case 'probably_not_exploitable':
        return 'info';
      case 'not_exploitable':
        return 'success';
      default:
        return 'default';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'running':
        return 'success';
      case 'paused':
        return 'warning';
      case 'completed':
        return 'info';
      case 'failed':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <AIIcon /> Agentic Binary Fuzzer
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        AI-powered autonomous binary vulnerability discovery with intelligent strategy selection
      </Typography>

      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {/* Environment Status Warning */}
      {envStatus?.mock_mode && (
        <Alert severity="warning" sx={{ mb: 2 }} icon={<WarningIcon />}>
          <Typography variant="subtitle2" sx={{ fontWeight: 'bold' }}>
            Mock Mode Active - AFL++ Not Available
          </Typography>
          <Typography variant="body2">
            {envStatus.warning || 'The fuzzing engine is running in simulation mode. Results are not from real fuzzing.'}
            {' '}Install AFL++ for actual vulnerability discovery.
          </Typography>
        </Alert>
      )}

      {/* Environment Status Info */}
      {envStatus && !envStatus.mock_mode && (
        <Alert severity="success" sx={{ mb: 2 }} icon={<CheckIcon />}>
          <Typography variant="body2">
            AFL++ {envStatus.afl_version || 'available'} • AI decisions every {envStatus.decision_interval_seconds}s (~{envStatus.estimated_ai_calls_per_hour}/hour)
          </Typography>
        </Alert>
      )}

      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 2 }}>
        <Tab label="Analysis" icon={<AnalyticsIcon />} iconPosition="start" />
        <Tab label="Campaign" icon={<BugIcon />} iconPosition="start" />
        <Tab label="Crashes" icon={<WarningIcon />} iconPosition="start" />
        <Tab label="AI Decisions" icon={<AIIcon />} iconPosition="start" />
        <Tab label="History" icon={<TimelineIcon />} iconPosition="start" />
        <Tab label="Reports" icon={<ReportIcon />} iconPosition="start" />
      </Tabs>

      {/* Analysis Tab */}
      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Upload Binary
                </Typography>

                <Box
                  {...getRootProps()}
                  sx={{
                    border: '2px dashed',
                    borderColor: isDragActive ? 'primary.main' : 'grey.500',
                    borderRadius: 2,
                    p: 4,
                    textAlign: 'center',
                    cursor: 'pointer',
                    bgcolor: isDragActive ? 'action.hover' : 'background.paper',
                    mb: 2,
                  }}
                >
                  <input {...getInputProps()} />
                  <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
                  <Typography>
                    {isDragActive
                      ? 'Drop the binary here...'
                      : 'Drag & drop a binary, or click to select'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Supports ELF, PE, Mach-O binaries
                  </Typography>
                </Box>

                {selectedFile && (
                  <Alert severity="info" icon={<MemoryIcon />}>
                    Selected: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(1)} KB)
                  </Alert>
                )}

                {loading && <LinearProgress sx={{ mt: 2 }} />}
              </CardContent>
            </Card>
          </Grid>

          <Grid item xs={12} md={6}>
            {analysis && (
              <Card>
                <CardContent>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SecurityIcon /> Quick Analysis
                  </Typography>

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Type</Typography>
                      <Typography>{analysis.file_type} ({analysis.architecture})</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Size</Typography>
                      <Typography>{(analysis.size_bytes / 1024).toFixed(1)} KB</Typography>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Attack Surface</Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={analysis.attack_surface_score * 100}
                          sx={{ flex: 1, height: 8, borderRadius: 1 }}
                          color={analysis.attack_surface_score > 0.6 ? 'error' : analysis.attack_surface_score > 0.3 ? 'warning' : 'success'}
                        />
                        <Typography variant="body2">
                          {(analysis.attack_surface_score * 100).toFixed(0)}%
                        </Typography>
                      </Box>
                    </Grid>
                    <Grid item xs={6}>
                      <Typography variant="caption" color="text.secondary">Difficulty</Typography>
                      <Chip
                        label={analysis.estimated_difficulty}
                        size="small"
                        color={
                          analysis.estimated_difficulty === 'easy' ? 'success' :
                          analysis.estimated_difficulty === 'medium' ? 'warning' : 'error'
                        }
                      />
                    </Grid>

                    <Grid item xs={12}>
                      <Typography variant="caption" color="text.secondary">Protections</Typography>
                      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                        {Object.entries(analysis.protections).map(([name, enabled]) => (
                          <Chip
                            key={name}
                            label={name.toUpperCase()}
                            size="small"
                            icon={enabled ? <CheckIcon /> : <ErrorIcon />}
                            color={enabled ? 'success' : 'error'}
                            variant="outlined"
                          />
                        ))}
                      </Box>
                    </Grid>

                    {analysis.dangerous_functions.length > 0 && (
                      <Grid item xs={12}>
                        <Typography variant="caption" color="text.secondary">Dangerous Functions</Typography>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 0.5 }}>
                          {analysis.dangerous_functions.map((func) => (
                            <Chip key={func} label={func} size="small" color="warning" variant="outlined" />
                          ))}
                        </Box>
                      </Grid>
                    )}

                    {analysis.ai_recommendation && (
                      <Grid item xs={12}>
                        <Alert severity="info" icon={<AIIcon />}>
                          <Typography variant="body2">{analysis.ai_recommendation}</Typography>
                        </Alert>
                      </Grid>
                    )}

                    <Grid item xs={12}>
                      <Button
                        variant="contained"
                        startIcon={<PlayIcon />}
                        onClick={() => setConfigDialog(true)}
                        disabled={loading}
                        fullWidth
                      >
                        Start Fuzzing Campaign
                      </Button>
                    </Grid>
                  </Grid>
                </CardContent>
              </Card>
            )}
          </Grid>
        </Grid>
      </TabPanel>

      {/* Campaign Tab */}
      <TabPanel value={activeTab} index={1}>
        {activeCampaign ? (
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Box>
                      <Typography variant="h6">
                        Campaign: {activeCampaign.campaign_id}
                      </Typography>
                      <Chip
                        label={activeCampaign.status}
                        color={getStatusColor(activeCampaign.status) as any}
                        size="small"
                      />
                    </Box>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      {activeCampaign.status === 'running' && (
                        <Button variant="outlined" startIcon={<PauseIcon />} onClick={pauseCampaign}>
                          Pause
                        </Button>
                      )}
                      {activeCampaign.status === 'paused' && (
                        <Button variant="outlined" startIcon={<PlayIcon />} onClick={resumeCampaign}>
                          Resume
                        </Button>
                      )}
                      {['running', 'paused'].includes(activeCampaign.status) && (
                        <Button variant="outlined" color="error" startIcon={<StopIcon />} onClick={stopCampaign}>
                          Stop
                        </Button>
                      )}
                      <IconButton onClick={() => refreshCampaignStatus(activeCampaign.campaign_id)}>
                        <RefreshIcon />
                      </IconButton>
                    </Box>
                  </Box>

                  <Grid container spacing={3}>
                    <Grid item xs={6} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="h4" color="primary">
                          {activeCampaign.coverage_percentage.toFixed(1)}%
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Coverage</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="h4" color="error">
                          {activeCampaign.unique_crashes}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Crashes</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="h4" color="warning.main">
                          {activeCampaign.exploitable_crashes}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Exploitable</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={3}>
                      <Paper sx={{ p: 2, textAlign: 'center' }}>
                        <Typography variant="h4">
                          {activeCampaign.executions_per_second.toFixed(0)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">Exec/sec</Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  <Box sx={{ mt: 3 }}>
                    <Typography variant="body2" color="text.secondary">
                      Elapsed: {activeCampaign.elapsed_time || 'N/A'} |
                      Executions: {activeCampaign.total_executions.toLocaleString()} |
                      Corpus: {activeCampaign.corpus_size} |
                      Strategy: {activeCampaign.current_strategy || 'N/A'} |
                      AI Decisions: {activeCampaign.decisions_made}
                    </Typography>
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        ) : (
          <Alert severity="info">
            No active campaign. Upload a binary and start a campaign from the Analysis tab.
          </Alert>
        )}
      </TabPanel>

      {/* Crashes Tab */}
      <TabPanel value={activeTab} index={2}>
        {crashes.length > 0 ? (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Crash ID</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Exploitability</TableCell>
                  <TableCell>Confidence</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {crashes.map((crash) => (
                  <TableRow key={crash.crash_id}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {crash.crash_id}
                      </Typography>
                    </TableCell>
                    <TableCell>{crash.crash_type}</TableCell>
                    <TableCell>
                      <Chip
                        label={crash.exploitability}
                        size="small"
                        color={getExploitabilityColor(crash.exploitability) as any}
                      />
                    </TableCell>
                    <TableCell>{(crash.confidence * 100).toFixed(0)}%</TableCell>
                    <TableCell>
                      <Tooltip title="View Details">
                        <IconButton size="small">
                          <InfoIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Generate Exploit">
                        <IconButton size="small">
                          <CodeIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Download">
                        <IconButton size="small">
                          <DownloadIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Alert severity="info">No crashes found yet.</Alert>
        )}
      </TabPanel>

      {/* AI Decisions Tab */}
      <TabPanel value={activeTab} index={3}>
        {decisions.length > 0 ? (
          <List>
            {decisions.map((decision) => (
              <ListItem key={decision.decision_id} divider>
                <ListItemIcon>
                  <AIIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip label={decision.type} size="small" variant="outlined" />
                      <Typography variant="caption" color="text.secondary">
                        {new Date(decision.timestamp).toLocaleString()}
                      </Typography>
                    </Box>
                  }
                  secondary={decision.reasoning}
                />
              </ListItem>
            ))}
          </List>
        ) : (
          <Alert severity="info">No AI decisions recorded yet.</Alert>
        )}
      </TabPanel>

      {/* History Tab */}
      <TabPanel value={activeTab} index={4}>
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Campaign ID</TableCell>
                <TableCell>Binary</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Started</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {campaigns.map((campaign) => (
                <TableRow key={campaign.campaign_id}>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {campaign.campaign_id}
                    </Typography>
                  </TableCell>
                  <TableCell>{campaign.binary_name || 'N/A'}</TableCell>
                  <TableCell>
                    <Chip
                      label={campaign.status}
                      size="small"
                      color={getStatusColor(campaign.status) as any}
                    />
                  </TableCell>
                  <TableCell>{campaign.elapsed_time || 'N/A'}</TableCell>
                  <TableCell>
                    <Button
                      size="small"
                      onClick={() => {
                        setActiveCampaign(campaign);
                        setActiveTab(1);
                        refreshCampaignStatus(campaign.campaign_id);
                      }}
                    >
                      View
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Reports Tab */}
      <TabPanel value={activeTab} index={5}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h6">Saved Campaign Reports</Typography>
          <Button startIcon={<RefreshIcon />} onClick={loadReports}>
            Refresh
          </Button>
        </Box>

        {reports.length > 0 ? (
          <TableContainer component={Paper}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>Binary</TableCell>
                  <TableCell>Risk</TableCell>
                  <TableCell>Coverage</TableCell>
                  <TableCell>Crashes</TableCell>
                  <TableCell>Duration</TableCell>
                  <TableCell>Date</TableCell>
                  <TableCell>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id}>
                    <TableCell>
                      <Typography variant="body2" fontWeight="bold">
                        {report.binary_name}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                        {report.campaign_id}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {report.risk_rating && (
                        <Chip
                          label={report.risk_rating}
                          size="small"
                          color={getRiskColor(report.risk_rating) as any}
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      {report.final_coverage != null ? `${report.final_coverage.toFixed(1)}%` : 'N/A'}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Chip label={`${report.unique_crashes} total`} size="small" variant="outlined" />
                        {report.exploitable_crashes > 0 && (
                          <Chip
                            label={`${report.exploitable_crashes} exploitable`}
                            size="small"
                            color="error"
                          />
                        )}
                      </Box>
                    </TableCell>
                    <TableCell>{formatDuration(report.duration_seconds)}</TableCell>
                    <TableCell>
                      {new Date(report.created_at).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        <Tooltip title="View Report">
                          <IconButton size="small" onClick={() => viewReport(report.campaign_id)}>
                            <OpenIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export Markdown">
                          <IconButton size="small" onClick={() => exportReport(report.campaign_id, 'md')}>
                            <DownloadIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export PDF">
                          <IconButton size="small" onClick={() => exportReport(report.campaign_id, 'pdf')}>
                            <PdfIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Export Word">
                          <IconButton size="small" onClick={() => exportReport(report.campaign_id, 'docx')}>
                            <WordIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton size="small" color="error" onClick={() => deleteReport(report.campaign_id)}>
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Alert severity="info">
            No saved reports yet. Reports are automatically generated when campaigns complete.
          </Alert>
        )}
      </TabPanel>

      {/* Configuration Dialog */}
      <Dialog open={configDialog} onClose={() => setConfigDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Campaign Configuration</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 3 }}>
            {/* Mock Mode Warning in Dialog */}
            {envStatus?.mock_mode && (
              <Alert severity="warning" icon={<WarningIcon />}>
                <Typography variant="body2" sx={{ fontWeight: 'bold' }}>
                  Mock Mode - Results will be simulated
                </Typography>
                <Typography variant="caption">
                  AFL++ is not available. Install it for real fuzzing results.
                </Typography>
              </Alert>
            )}
            <FormControl fullWidth>
              <InputLabel>Initial Strategy</InputLabel>
              <Select
                value={config.strategy}
                label="Initial Strategy"
                onChange={(e) => setConfig({ ...config, strategy: e.target.value })}
              >
                <MenuItem value="coverage_guided">Coverage Guided</MenuItem>
                <MenuItem value="directed_fuzzing">Directed Fuzzing</MenuItem>
                <MenuItem value="grammar_based">Grammar Based</MenuItem>
                <MenuItem value="exploit_oriented">Exploit Oriented</MenuItem>
              </Select>
            </FormControl>

            <Box>
              <Typography gutterBottom sx={{ mb: 1 }}>
                Duration: {config.maxDurationHours < 1 ? `${config.maxDurationHours * 60} minutes` : `${config.maxDurationHours} hour${config.maxDurationHours !== 1 ? 's' : ''}`}
              </Typography>

              {/* Duration Presets */}
              <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                {durationPresets.map((preset) => (
                  <Tooltip
                    key={preset.label}
                    title={`${preset.description} • ~${preset.aiCalls} AI calls`}
                  >
                    <Chip
                      label={preset.label}
                      onClick={() => setConfig({ ...config, maxDurationHours: preset.hours })}
                      color={config.maxDurationHours === preset.hours ? 'primary' : 'default'}
                      variant={config.maxDurationHours === preset.hours ? 'filled' : 'outlined'}
                      sx={{ minWidth: 80 }}
                    />
                  </Tooltip>
                ))}
              </Box>

              {/* Custom Duration Slider */}
              <Typography variant="caption" color="text.secondary" gutterBottom>
                Or set custom duration:
              </Typography>
              <Slider
                value={config.maxDurationHours}
                onChange={(_, v) => setConfig({ ...config, maxDurationHours: v as number })}
                min={0.5}
                max={72}
                step={0.5}
                valueLabelDisplay="auto"
                valueLabelFormat={(v) => v < 1 ? `${v * 60}m` : `${v}h`}
                marks={[
                  { value: 0.5, label: '30m' },
                  { value: 2, label: '2h' },
                  { value: 8, label: '8h' },
                  { value: 24, label: '24h' },
                  { value: 72, label: '72h' },
                ]}
              />
            </Box>

            <Box>
              <Typography gutterBottom>Fuzzing Engines: {config.maxEngines}</Typography>
              <Slider
                value={config.maxEngines}
                onChange={(_, v) => setConfig({ ...config, maxEngines: v as number })}
                min={1}
                max={8}
                valueLabelDisplay="auto"
              />
            </Box>

            <FormControlLabel
              control={
                <Switch
                  checked={config.enableAI}
                  onChange={(e) => setConfig({ ...config, enableAI: e.target.checked })}
                />
              }
              label="Enable AI Decision Making"
            />

            <FormControlLabel
              control={
                <Switch
                  checked={config.stopOnExploitable}
                  onChange={(e) => setConfig({ ...config, stopOnExploitable: e.target.checked })}
                />
              }
              label="Stop on Exploitable Crash"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfigDialog(false)}>Cancel</Button>
          <Button variant="contained" onClick={startCampaign} disabled={loading}>
            {loading ? <CircularProgress size={24} /> : 'Start Campaign'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Report Viewer Dialog */}
      <Dialog
        open={reportDialogOpen}
        onClose={() => setReportDialogOpen(false)}
        maxWidth="lg"
        fullWidth
        PaperProps={{ sx: { minHeight: '80vh' } }}
      >
        <DialogTitle sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="h6">Campaign Report</Typography>
            {selectedReport && (
              <Typography variant="caption" color="text.secondary">
                {selectedReport.binary_name} - {selectedReport.campaign_id}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Tooltip title="Export Markdown">
              <IconButton onClick={() => selectedReport && exportReport(selectedReport.campaign_id, 'md')}>
                <DownloadIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Export PDF">
              <IconButton onClick={() => selectedReport && exportReport(selectedReport.campaign_id, 'pdf')}>
                <PdfIcon />
              </IconButton>
            </Tooltip>
            <Tooltip title="Export Word">
              <IconButton onClick={() => selectedReport && exportReport(selectedReport.campaign_id, 'docx')}>
                <WordIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {loadingReport ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
              <CircularProgress />
            </Box>
          ) : selectedReport ? (
            <Box>
              {/* Executive Summary */}
              <Paper sx={{ p: 2, mb: 3 }}>
                <Typography variant="h6" gutterBottom>Executive Summary</Typography>
                {selectedReport.report_data?.risk_rating && (
                  <Chip
                    label={selectedReport.report_data.risk_rating}
                    color={getRiskColor(selectedReport.report_data.risk_rating) as any}
                    sx={{ mb: 2 }}
                  />
                )}
                <Typography variant="body1">
                  {selectedReport.executive_summary || 'No summary available.'}
                </Typography>
              </Paper>

              {/* Key Metrics */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="primary">
                      {selectedReport.final_coverage?.toFixed(1) || 0}%
                    </Typography>
                    <Typography variant="caption">Coverage</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4">
                      {selectedReport.total_executions?.toLocaleString() || 0}
                    </Typography>
                    <Typography variant="caption">Executions</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="warning.main">
                      {selectedReport.unique_crashes || 0}
                    </Typography>
                    <Typography variant="caption">Crashes</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="error">
                      {selectedReport.exploitable_crashes || 0}
                    </Typography>
                    <Typography variant="caption">Exploitable</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4">
                      {selectedReport.total_decisions || 0}
                    </Typography>
                    <Typography variant="caption">AI Decisions</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4">
                      {formatDuration(selectedReport.duration_seconds)}
                    </Typography>
                    <Typography variant="caption">Duration</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* Key Findings */}
              {selectedReport.report_data?.key_findings && selectedReport.report_data.key_findings.length > 0 && (
                <Paper sx={{ p: 2, mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Key Findings</Typography>
                  <List dense>
                    {selectedReport.report_data.key_findings.map((finding, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon>
                          <InfoIcon color="info" />
                        </ListItemIcon>
                        <ListItemText primary={finding} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}

              {/* Recommendations */}
              {selectedReport.recommendations && (
                <Paper sx={{ p: 2, mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Recommendations</Typography>
                  <List dense>
                    {selectedReport.recommendations.split('\n').filter(r => r.trim()).map((rec, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon>
                          <SecurityIcon color="warning" />
                        </ListItemIcon>
                        <ListItemText primary={rec} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}

              {/* Crashes */}
              {selectedReport.crashes && selectedReport.crashes.length > 0 && (
                <Paper sx={{ p: 2, mb: 3 }}>
                  <Typography variant="h6" gutterBottom>Crash Analysis</Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Exploitability</TableCell>
                          <TableCell>Confidence</TableCell>
                          <TableCell>Impact</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {selectedReport.crashes.map((crash, idx) => (
                          <TableRow key={idx}>
                            <TableCell>{crash.crash_type}</TableCell>
                            <TableCell>
                              <Chip
                                label={crash.exploitability}
                                size="small"
                                color={getExploitabilityColor(crash.exploitability) as any}
                              />
                            </TableCell>
                            <TableCell>{(crash.confidence * 100).toFixed(0)}%</TableCell>
                            <TableCell>
                              <Typography variant="body2" sx={{ maxWidth: 300 }}>
                                {crash.impact || 'N/A'}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Paper>
              )}

              {/* AI Decisions */}
              {selectedReport.decisions && selectedReport.decisions.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>AI Decision History ({selectedReport.decisions.length} decisions)</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TableContainer>
                      <Table size="small">
                        <TableHead>
                          <TableRow>
                            <TableCell>Time</TableCell>
                            <TableCell>Decision</TableCell>
                            <TableCell>Reasoning</TableCell>
                          </TableRow>
                        </TableHead>
                        <TableBody>
                          {selectedReport.decisions.slice(0, 20).map((decision, idx) => (
                            <TableRow key={idx}>
                              <TableCell>
                                {new Date(decision.timestamp).toLocaleTimeString()}
                              </TableCell>
                              <TableCell>
                                <Chip label={decision.decision_type} size="small" variant="outlined" />
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2" sx={{ maxWidth: 400 }}>
                                  {decision.reasoning.slice(0, 150)}
                                  {decision.reasoning.length > 150 && '...'}
                                </Typography>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </TableContainer>
                    {selectedReport.decisions.length > 20 && (
                      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                        Showing first 20 of {selectedReport.decisions.length} decisions
                      </Typography>
                    )}
                  </AccordionDetails>
                </Accordion>
              )}
            </Box>
          ) : (
            <Alert severity="info">No report data available.</Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setReportDialogOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
