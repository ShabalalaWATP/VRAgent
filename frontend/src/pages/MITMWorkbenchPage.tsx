import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  IconButton,
  Card,
  CardContent,
  CardActions,
  Chip,
  Switch,
  FormControlLabel,
  Checkbox,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  InputAdornment,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tabs,
  Tab,
  Alert,
  Tooltip,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Badge,
  LinearProgress,
  Snackbar,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  CircularProgress,
  Menu,
  ListItemIcon,
  Collapse,
  AlertTitle,
  Avatar,
  Fade,
  Backdrop,
  Zoom,
  useTheme,
  alpha,
} from '@mui/material';
import {
  PlayArrow as PlayIcon,
  Stop as StopIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  Refresh as RefreshIcon,
  ExpandMore as ExpandMoreIcon,
  FilterList as FilterIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Code as CodeIcon,
  Http as HttpIcon,
  Lock as LockIcon,
  LockOpen as LockOpenIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Clear as ClearIcon,
  Visibility as ViewIcon,
  Edit as EditIcon,
  Rule as RuleIcon,
  NetworkCheck as NetworkIcon,
  SwapHoriz as SwapIcon,
  Warning as WarningIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Settings as SettingsIcon,
  HelpOutline as HelpIcon,
  School as TutorialIcon,
  Psychology as AIIcon,
  Description as MarkdownIcon,
  PictureAsPdf as PdfIcon,
  Article as WordIcon,
  TipsAndUpdates as TipIcon,
  ArrowForward as NextIcon,
  ArrowBack as BackIcon,
  BugReport as DebugIcon,
  Lightbulb as IdeaIcon,
  VerifiedUser as ShieldIcon,
  Science as ScienceIcon,
  PlayCircle as RunIcon,
  CheckCircleOutline as CheckIcon,
  Cancel as CancelIcon,
  Info as InfoIcon,
  Computer as ClientIcon,
  Storage as ServerIcon,
  Router as ProxyIcon,
  East as ArrowRightIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
  FiberManualRecord as DotIcon,
  Close as CloseIcon,
  MenuBook as LearnIcon,
  ArrowDropDown as DropdownIcon,
  Search as SearchIcon,
  MoreVert as MoreIcon,
  Replay as ReplayIcon,
  History as HistoryIcon,
} from '@mui/icons-material';
import { 
  mitmClient, 
  MITMAnalysisResult, 
  MITMGuidedSetup, 
  MITMTestScenario, 
  MITMProxyHealth, 
  NaturalLanguageRuleResponse, 
  AISuggestion, 
  AISuggestionsResponse, 
  MITMSession,
  WebSocketConnection,
  WebSocketFrame,
  WebSocketRule,
  WebSocketStats,
  CACertificate,
  HostCertificate,
  CertificateInstallationInstructions,
} from '../api/client';

// Types
interface ProxyInstance {
  id: string;
  listen_host: string;
  listen_port: number;
  target_host: string;
  target_port: number;
  mode: 'passthrough' | 'intercept' | 'auto_modify';
  tls_enabled: boolean;
  running: boolean;
  stats: {
    requests: number;
    responses: number;
    bytes_sent: number;
    bytes_received: number;
    errors: number;
    rules_applied: number;
  };
}

interface TrafficEntry {
  id: string;
  timestamp: string;
  request: {
    method: string;
    path: string;
    host?: string;
    url?: string;
    protocol?: string;
    headers: Record<string, string>;
    body?: string;
    body_text?: string;
  };
  response?: {
    status_code: number;
    status_text: string;
    status_message?: string;
    headers: Record<string, string>;
    body?: string;
    body_text?: string;
    response_time_ms?: number;
  };
  duration_ms: number;
  modified: boolean;
  rules_applied: string[];
  tags?: string[];
  notes?: string;
}

interface InterceptionRule {
  id: string;
  name: string;
  enabled: boolean;
  priority?: number;
  group?: string | null;
  match_direction: 'request' | 'response' | 'both';
  match_host?: string;
  match_path?: string;
  match_method?: string;
  match_content_type?: string;
  match_status_code?: number;
  match_query?: Record<string, string>;
  action: 'modify' | 'drop' | 'delay';
  modify_headers?: Record<string, string>;
  remove_headers?: string[];
  modify_body?: string;
  body_find_replace?: Record<string, string>;
  body_find_replace_regex?: boolean;
  json_path_edits?: Array<{ path: string; op?: string; value?: any }>;
  modify_status_code?: number;
  modify_path?: string;
  delay_ms?: number;
  hit_count?: number;
}

interface PresetRule {
  id: string;
  name: string;
  description?: string;
}

const API_TESTER_HANDOFF_KEY = 'vragent-api-tester-handoff';
const FUZZER_HANDOFF_KEY = 'vragent-fuzzer-handoff';

// Tab panel component
function TabPanel({ children, value, index }: { children: React.ReactNode; value: number; index: number }) {
  return (
    <div hidden={value !== index} style={{ height: '100%' }}>
      {value === index && <Box sx={{ p: 2, height: '100%' }}>{children}</Box>}
    </div>
  );
}

const MITMWorkbenchPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const projectId = searchParams.get('projectId');
  const projectName = searchParams.get('projectName');

  // State
  const [proxies, setProxies] = useState<ProxyInstance[]>([]);
  const [selectedProxy, setSelectedProxy] = useState<string | null>(null);
  const [traffic, setTraffic] = useState<TrafficEntry[]>([]);
  const [trafficSearch, setTrafficSearch] = useState('');
  const [trafficMethodFilter, setTrafficMethodFilter] = useState<string[]>([]);
  const [trafficStatusFilter, setTrafficStatusFilter] = useState('all');
  const [trafficHostFilter, setTrafficHostFilter] = useState('all');
  const [trafficModifiedOnly, setTrafficModifiedOnly] = useState(false);
  const [trafficWithResponseOnly, setTrafficWithResponseOnly] = useState(false);
  const [trafficSort, setTrafficSort] = useState<'newest' | 'oldest'>('newest');
  const [rules, setRules] = useState<InterceptionRule[]>([]);
  const [presets, setPresets] = useState<PresetRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);

  // New proxy dialog
  const [newProxyOpen, setNewProxyOpen] = useState(false);
  const [newProxy, setNewProxy] = useState({
    proxy_id: '',
    listen_host: '127.0.0.1',
    listen_port: 8080,
    target_host: 'localhost',
    target_port: 80,
    mode: 'passthrough',
    tls_enabled: false,
  });

  // New rule dialog
  const [newRuleOpen, setNewRuleOpen] = useState(false);
  const [newRule, setNewRule] = useState<Partial<InterceptionRule>>({
    name: '',
    enabled: true,
    match_direction: 'both',
    action: 'modify',
  });
  const [ruleMatchQueryInput, setRuleMatchQueryInput] = useState('');
  const [ruleModifyHeadersInput, setRuleModifyHeadersInput] = useState('');
  const [ruleRemoveHeadersInput, setRuleRemoveHeadersInput] = useState('');
  const [ruleBodyFindReplaceInput, setRuleBodyFindReplaceInput] = useState('');
  const [ruleJsonPathEditsInput, setRuleJsonPathEditsInput] = useState('');

  // Traffic detail dialog
  const [trafficDetailOpen, setTrafficDetailOpen] = useState(false);
  const [selectedTraffic, setSelectedTraffic] = useState<TrafficEntry | null>(null);
  const [trafficNotes, setTrafficNotes] = useState('');
  const [trafficTagsInput, setTrafficTagsInput] = useState('');
  const [savingTrafficMeta, setSavingTrafficMeta] = useState(false);
  const [trafficMenuAnchor, setTrafficMenuAnchor] = useState<null | HTMLElement>(null);
  const [trafficMenuEntry, setTrafficMenuEntry] = useState<TrafficEntry | null>(null);

  // Live stream (WebSocket)
  const [liveStreamEnabled, setLiveStreamEnabled] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsError, setWsError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  // Sessions
  const [sessionsOpen, setSessionsOpen] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(false);
  const [sessions, setSessions] = useState<MITMSession[]>([]);
  const [activeSession, setActiveSession] = useState<MITMSession | null>(null);
  const [sessionName, setSessionName] = useState('');

  // Traffic export menu state
  const [trafficExportAnchorEl, setTrafficExportAnchorEl] = useState<null | HTMLElement>(null);
  const [trafficExporting, setTrafficExporting] = useState(false);

  // Replay state
  const [replayOpen, setReplayOpen] = useState(false);
  const [replayLoading, setReplayLoading] = useState(false);
  const [replayEntry, setReplayEntry] = useState<TrafficEntry | null>(null);
  const [replayOverrides, setReplayOverrides] = useState({
    method: '',
    path: '',
    body: '',
    addHeaders: '',
    removeHeaders: '',
    baseUrl: '',
    timeout: 20,
    verifyTls: false,
  });

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(false);

  // Guided wizard state
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [guidedSetup, setGuidedSetup] = useState<MITMGuidedSetup | null>(null);
  const [loadingGuide, setLoadingGuide] = useState(false);

  // AI Analysis state
  const [analysisResult, setAnalysisResult] = useState<MITMAnalysisResult | null>(null);
  const [analyzingTraffic, setAnalyzingTraffic] = useState(false);
  const [showAnalysis, setShowAnalysis] = useState(false);

  // Export menu state
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);

  // Beginner Features: Test Scenarios
  const [testScenarios, setTestScenarios] = useState<MITMTestScenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<MITMTestScenario | null>(null);
  const [scenarioDialogOpen, setScenarioDialogOpen] = useState(false);
  const [runningScenario, setRunningScenario] = useState(false);
  const [scenarioResult, setScenarioResult] = useState<any>(null);

  // Beginner Features: Health Check
  const [proxyHealth, setProxyHealth] = useState<MITMProxyHealth | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);

  // Beginner Features: Interactive Tutorial
  const [tutorialActive, setTutorialActive] = useState(false);
  const [tutorialStep, setTutorialStep] = useState(0);
  const [showBeginnerBanner, setShowBeginnerBanner] = useState(true);

  // Natural Language Rule Creation
  const [nlRuleInput, setNlRuleInput] = useState('');
  const [nlRuleLoading, setNlRuleLoading] = useState(false);
  const [nlRuleResult, setNlRuleResult] = useState<NaturalLanguageRuleResponse | null>(null);
  const [showNlRulePanel, setShowNlRulePanel] = useState(false);

  // AI Suggestions
  const [aiSuggestions, setAiSuggestions] = useState<AISuggestion[]>([]);
  const [aiSuggestionsLoading, setAiSuggestionsLoading] = useState(false);
  const [showAiSuggestions, setShowAiSuggestions] = useState(false);
  const [aiSuggestionsResponse, setAiSuggestionsResponse] = useState<AISuggestionsResponse | null>(null);

  // WebSocket Deep Inspection State
  const [wsConnections, setWsConnections] = useState<WebSocketConnection[]>([]);
  const [wsFrames, setWsFrames] = useState<WebSocketFrame[]>([]);
  const [wsRules, setWsRules] = useState<WebSocketRule[]>([]);
  const [wsStats, setWsStats] = useState<WebSocketStats | null>(null);
  const [selectedWsConnection, setSelectedWsConnection] = useState<string | null>(null);
  const [wsLoadingConnections, setWsLoadingConnections] = useState(false);
  const [wsLoadingFrames, setWsLoadingFrames] = useState(false);
  const [wsNewRuleOpen, setWsNewRuleOpen] = useState(false);
  const [wsNewRule, setWsNewRule] = useState<Partial<WebSocketRule>>({
    name: '',
    enabled: true,
    priority: 0,
    match_direction: 'both',
    action: 'passthrough',
    delay_ms: 0,
  });
  const [wsSelectedFrame, setWsSelectedFrame] = useState<WebSocketFrame | null>(null);

  // Certificate Management State
  const [caCertificate, setCaCertificate] = useState<CACertificate | null>(null);
  const [hostCertificates, setHostCertificates] = useState<HostCertificate[]>([]);
  const [certInstallInstructions, setCertInstallInstructions] = useState<CertificateInstallationInstructions | null>(null);
  const [certLoading, setCertLoading] = useState(false);
  const [certGenerating, setCertGenerating] = useState(false);
  const [showCertGenDialog, setShowCertGenDialog] = useState(false);
  const [certGenConfig, setCertGenConfig] = useState({
    common_name: 'VRAgent MITM CA',
    organization: 'VRAgent Security',
    country: 'US',
    validity_days: 365,
  });
  const [showCertInstallDialog, setShowCertInstallDialog] = useState(false);

  // Match & Replace Templates State
  const [templates, setTemplates] = useState<any[]>([]);
  const [templateCategories, setTemplateCategories] = useState<string[]>([]);
  const [templatesLoading, setTemplatesLoading] = useState(false);
  const [selectedTemplateCategory, setSelectedTemplateCategory] = useState<string>('');
  const [selectedTemplate, setSelectedTemplate] = useState<any | null>(null);
  const [showNewTemplateDialog, setShowNewTemplateDialog] = useState(false);
  const [newTemplate, setNewTemplate] = useState({
    name: '',
    category: 'Custom',
    description: '',
    match_type: 'header',
    match_pattern: '',
    replace_pattern: '',
    is_regex: false,
    case_sensitive: false,
    direction: 'both',
    tags: [] as string[],
  });
  const [templateTagsInput, setTemplateTagsInput] = useState('');
  const [testingTemplate, setTestingTemplate] = useState(false);
  const [templateTestResult, setTemplateTestResult] = useState<any | null>(null);

  // Traffic Diff Viewer State
  const [trafficDiff, setTrafficDiff] = useState<any | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffViewMode, setDiffViewMode] = useState<'unified' | 'side-by-side'>('side-by-side');

  // HTTP/2 & gRPC State
  const [http2Frames, setHttp2Frames] = useState<any[]>([]);
  const [http2Streams, setHttp2Streams] = useState<any[]>([]);
  const [grpcMessages, setGrpcMessages] = useState<any[]>([]);
  const [http2Loading, setHttp2Loading] = useState(false);
  const [selectedHttp2Stream, setSelectedHttp2Stream] = useState<number | null>(null);
  const [grpcServiceFilter, setGrpcServiceFilter] = useState('');

  // Theme for animations
  const theme = useTheme();

  const buildWsUrl = useCallback((proxyId: string) => {
    const base = import.meta.env.VITE_API_URL || '/api';
    const path = `/mitm/ws/${proxyId}`;
    if (base.startsWith('http://') || base.startsWith('https://')) {
      const wsBase = base.replace(/^http/, 'ws').replace(/\/$/, '');
      return `${wsBase}${path}`;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const normalizedBase = base.startsWith('/') ? base : `/${base}`;
    const baseTrimmed = normalizedBase.replace(/\/$/, '');
    return `${protocol}://${window.location.host}${baseTrimmed}${path}`;
  }, []);

  const normalizeTrafficEntry = useCallback((entry: any): TrafficEntry => {
    const request = entry.request || {};
    const response = entry.response || undefined;
    const timestamp = entry.timestamp || request.timestamp || new Date().toISOString();
    const duration = entry.duration_ms ?? response?.response_time_ms ?? 0;
    const modified = entry.modified ?? (request.modified || response?.modified || false);

    return {
      id: entry.id,
      timestamp,
      request: {
        method: request.method || 'UNKNOWN',
        path: request.path || '/',
        host: request.host,
        url: request.url,
        protocol: request.protocol,
        headers: request.headers || {},
        body: request.body ?? request.body_text ?? undefined,
        body_text: request.body_text ?? request.body ?? undefined,
      },
      response: response ? {
        status_code: response.status_code ?? 0,
        status_text: response.status_text || response.status_message || '',
        status_message: response.status_message,
        headers: response.headers || {},
        body: response.body ?? response.body_text ?? undefined,
        body_text: response.body_text ?? response.body ?? undefined,
        response_time_ms: response.response_time_ms ?? duration,
      } : undefined,
      duration_ms: duration,
      modified,
      rules_applied: entry.rules_applied || [],
      tags: entry.tags,
      notes: entry.notes,
    };
  }, []);

  // Load proxies
  const loadProxies = useCallback(async () => {
    try {
      const data = await mitmClient.listProxies();
      const normalized = (data || []).map((proxy: any) => ({
        id: proxy.id,
        listen_host: proxy.listen_host || '127.0.0.1',
        listen_port: proxy.listen_port ?? 0,
        target_host: proxy.target_host || '',
        target_port: proxy.target_port ?? 0,
        mode: proxy.mode || 'passthrough',
        tls_enabled: Boolean(proxy.tls_enabled),
        running: Boolean(proxy.running),
        stats: {
          requests: proxy.stats?.requests ?? proxy.requests ?? proxy.requests_total ?? 0,
          responses: proxy.stats?.responses ?? proxy.responses ?? proxy.responses_total ?? 0,
          bytes_sent: proxy.stats?.bytes_sent ?? proxy.bytes_sent ?? 0,
          bytes_received: proxy.stats?.bytes_received ?? proxy.bytes_received ?? 0,
          errors: proxy.stats?.errors ?? proxy.errors ?? 0,
          rules_applied: proxy.stats?.rules_applied ?? proxy.rules_applied ?? 0,
        },
      }));
      setProxies(normalized);
    } catch (err: any) {
      console.error('Failed to load proxies:', err);
    }
  }, []);

  // Load traffic for selected proxy
  const loadTraffic = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const data = await mitmClient.getTraffic(selectedProxy);
      const entries = (data as any)?.entries || [];
      const normalized = entries.map((entry: any) => normalizeTrafficEntry(entry));
      setTraffic(normalized);
    } catch (err: any) {
      console.error('Failed to load traffic:', err);
    }
  }, [selectedProxy, normalizeTrafficEntry]);

  // Load rules for selected proxy
  const loadRules = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const data = await mitmClient.getRules(selectedProxy);
      setRules(data || []);
    } catch (err: any) {
      console.error('Failed to load rules:', err);
    }
  }, [selectedProxy]);

  // Load preset rules
  const loadPresets = useCallback(async () => {
    try {
      const data = await mitmClient.getPresets();
      setPresets(data || []);
    } catch (err: any) {
      console.error('Failed to load presets:', err);
    }
  }, []);

  const loadSessions = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      const data = await mitmClient.listSessions(selectedProxy);
      setSessions(data || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load sessions');
    } finally {
      setSessionsLoading(false);
    }
  }, [selectedProxy]);

  const handleOpenSessions = async () => {
    setSessionsOpen(true);
    await loadSessions();
  };

  const handleCreateSession = async () => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      await mitmClient.createSession(selectedProxy, sessionName.trim() || undefined);
      setSessionName('');
      await loadSessions();
      setSuccess('Session saved');
    } catch (err: any) {
      setError(err.message || 'Failed to save session');
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleLoadSession = async (sessionId: string) => {
    if (!selectedProxy) return;
    try {
      setSessionsLoading(true);
      const response = await mitmClient.getSession(selectedProxy, sessionId, 200, 0);
      const entries = response?.entries || [];
      setTraffic(entries.map((entry: any) => normalizeTrafficEntry(entry)));
      const meta = response?.meta || sessions.find(session => session.id === sessionId);
      if (meta) {
        setActiveSession(meta);
      } else {
        setActiveSession({
          id: sessionId,
          name: sessionId,
          created_at: new Date().toISOString(),
          entries: response?.total || entries.length,
        });
      }
      setSelectedTraffic(null);
      setSessionsOpen(false);
    } catch (err: any) {
      setError(err.message || 'Failed to load session');
    } finally {
      setSessionsLoading(false);
    }
  };

  const handleExitSession = () => {
    setActiveSession(null);
    setSelectedTraffic(null);
    loadTraffic();
  };

  // Initial load
  useEffect(() => {
    loadProxies();
    loadPresets();
    loadTestScenarios();
  }, [loadProxies, loadPresets]);

  // Load test scenarios
  const loadTestScenarios = async () => {
    try {
      const data = await (mitmClient as any).getTestScenarios();
      setTestScenarios(data || []);
    } catch (err: any) {
      console.error('Failed to load test scenarios:', err);
    }
  };

  // Check proxy health
  const checkProxyHealth = async () => {
    if (!selectedProxy) return;
    try {
      setCheckingHealth(true);
      const health = await (mitmClient as any).checkProxyHealth(selectedProxy);
      setProxyHealth(health);
    } catch (err: any) {
      console.error('Failed to check proxy health:', err);
    } finally {
      setCheckingHealth(false);
    }
  };

  // WebSocket Deep Inspection Functions
  const loadWebSocketConnections = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      setWsLoadingConnections(true);
      const connections = await (mitmClient as any).getWebSocketConnections(selectedProxy);
      setWsConnections(connections || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket connections:', err);
    } finally {
      setWsLoadingConnections(false);
    }
  }, [selectedProxy]);

  const loadWebSocketFrames = useCallback(async (connectionId: string) => {
    if (!selectedProxy) return;
    try {
      setWsLoadingFrames(true);
      const result = await (mitmClient as any).getWebSocketFrames(selectedProxy, connectionId, 200, 0);
      setWsFrames(result?.frames || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket frames:', err);
    } finally {
      setWsLoadingFrames(false);
    }
  }, [selectedProxy]);

  const loadWebSocketStats = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const stats = await (mitmClient as any).getWebSocketStats(selectedProxy);
      setWsStats(stats);
    } catch (err: any) {
      console.error('Failed to load WebSocket stats:', err);
    }
  }, [selectedProxy]);

  const loadWebSocketRules = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const rules = await (mitmClient as any).getWebSocketRules(selectedProxy);
      setWsRules(rules || []);
    } catch (err: any) {
      console.error('Failed to load WebSocket rules:', err);
    }
  }, [selectedProxy]);

  const handleAddWebSocketRule = async () => {
    if (!selectedProxy) return;
    try {
      setLoading(true);
      await (mitmClient as any).addWebSocketRule(selectedProxy, wsNewRule);
      setSuccess('WebSocket rule added');
      setWsNewRuleOpen(false);
      setWsNewRule({
        name: '',
        enabled: true,
        priority: 0,
        match_direction: 'both',
        action: 'passthrough',
        delay_ms: 0,
      });
      loadWebSocketRules();
    } catch (err: any) {
      setError(err.message || 'Failed to add WebSocket rule');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveWebSocketRule = async (ruleId: string) => {
    if (!selectedProxy) return;
    try {
      await (mitmClient as any).removeWebSocketRule(selectedProxy, ruleId);
      setSuccess('WebSocket rule removed');
      loadWebSocketRules();
    } catch (err: any) {
      setError(err.message || 'Failed to remove WebSocket rule');
    }
  };

  // Certificate Management Functions
  const loadCACertificate = useCallback(async () => {
    try {
      setCertLoading(true);
      const cert = await (mitmClient as any).getCACertificate();
      if (cert && 'common_name' in cert) {
        setCaCertificate(cert as CACertificate);
      } else {
        setCaCertificate(null);
      }
    } catch (err: any) {
      console.error('Failed to load CA certificate:', err);
    } finally {
      setCertLoading(false);
    }
  }, []);

  const loadHostCertificates = useCallback(async () => {
    try {
      const certs = await (mitmClient as any).listHostCertificates();
      setHostCertificates(certs || []);
    } catch (err: any) {
      console.error('Failed to load host certificates:', err);
    }
  }, []);

  const loadCertificateInstallInstructions = useCallback(async () => {
    try {
      const instructions = await (mitmClient as any).getCertificateInstallationInstructions();
      setCertInstallInstructions(instructions);
    } catch (err: any) {
      console.error('Failed to load certificate installation instructions:', err);
    }
  }, []);

  const handleGenerateCACertificate = async () => {
    try {
      setCertGenerating(true);
      await (mitmClient as any).generateCACertificate(certGenConfig);
      setSuccess('CA certificate generated successfully');
      setShowCertGenDialog(false);
      loadCACertificate();
      loadHostCertificates();
    } catch (err: any) {
      setError(err.message || 'Failed to generate CA certificate');
    } finally {
      setCertGenerating(false);
    }
  };

  const handleDownloadCACertificate = async (format: 'pem' | 'crt' | 'der') => {
    try {
      const blob = await (mitmClient as any).downloadCACertificate(format);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vragent-ca.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSuccess(`CA certificate downloaded as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || 'Failed to download certificate');
    }
  };

  const handleDeleteHostCertificate = async (hostname: string) => {
    try {
      await (mitmClient as any).deleteHostCertificate(hostname);
      setSuccess(`Host certificate for ${hostname} deleted`);
      loadHostCertificates();
    } catch (err: any) {
      setError(err.message || 'Failed to delete host certificate');
    }
  };

  // Load certificates on mount
  useEffect(() => {
    loadCACertificate();
    loadHostCertificates();
  }, [loadCACertificate, loadHostCertificates]);

  // ========== Match & Replace Templates Functions ==========
  
  const loadTemplates = useCallback(async (category?: string) => {
    try {
      setTemplatesLoading(true);
      const data = await (mitmClient as any).getTemplates(category ? { category } : undefined);
      setTemplates(data || []);
    } catch (err: any) {
      console.error('Failed to load templates:', err);
    } finally {
      setTemplatesLoading(false);
    }
  }, []);

  const loadTemplateCategories = useCallback(async () => {
    try {
      const data = await (mitmClient as any).getTemplateCategories();
      setTemplateCategories(data.categories || []);
    } catch (err: any) {
      console.error('Failed to load template categories:', err);
    }
  }, []);

  const handleCreateTemplate = async () => {
    try {
      const tagsArray = templateTagsInput.split(',').map(t => t.trim()).filter(t => t);
      await (mitmClient as any).createTemplate({
        ...newTemplate,
        tags: tagsArray,
      });
      setSuccess('Custom template created!');
      setShowNewTemplateDialog(false);
      setNewTemplate({
        name: '',
        category: 'Custom',
        description: '',
        match_type: 'header',
        match_pattern: '',
        replace_pattern: '',
        is_regex: false,
        case_sensitive: false,
        direction: 'both',
        tags: [],
      });
      setTemplateTagsInput('');
      loadTemplates(selectedTemplateCategory || undefined);
    } catch (err: any) {
      setError(err.message || 'Failed to create template');
    }
  };

  const handleDeleteTemplate = async (templateId: string) => {
    try {
      await (mitmClient as any).deleteTemplate(templateId);
      setSuccess('Template deleted');
      loadTemplates(selectedTemplateCategory || undefined);
    } catch (err: any) {
      setError(err.message || 'Failed to delete template');
    }
  };

  const handleApplyTemplate = async (templateId: string) => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      await (mitmClient as any).applyTemplate(selectedProxy, templateId);
      setSuccess('Template applied as interception rule!');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to apply template');
    }
  };

  const handleTestTemplate = async (templateId: string) => {
    if (!selectedTraffic) {
      setError('Please select a traffic entry first');
      return;
    }
    try {
      setTestingTemplate(true);
      const result = await (mitmClient as any).testTemplate(
        templateId,
        selectedTraffic.request,
        selectedTraffic.response
      );
      setTemplateTestResult(result);
    } catch (err: any) {
      setError(err.message || 'Failed to test template');
    } finally {
      setTestingTemplate(false);
    }
  };

  // Load templates on mount
  useEffect(() => {
    loadTemplates();
    loadTemplateCategories();
  }, [loadTemplates, loadTemplateCategories]);

  // ========== Traffic Diff Viewer Functions ==========
  
  const loadTrafficDiff = useCallback(async (proxyId: string, entryId: string) => {
    try {
      setDiffLoading(true);
      const data = await (mitmClient as any).getTrafficDiff(proxyId, entryId);
      setTrafficDiff(data);
    } catch (err: any) {
      console.error('Failed to load traffic diff:', err);
      setTrafficDiff(null);
    } finally {
      setDiffLoading(false);
    }
  }, []);

  // Auto-load diff when viewing modified traffic
  useEffect(() => {
    if (selectedTraffic?.modified && selectedProxy) {
      loadTrafficDiff(selectedProxy, selectedTraffic.id);
    } else {
      setTrafficDiff(null);
    }
  }, [selectedTraffic, selectedProxy, loadTrafficDiff]);

  // ========== HTTP/2 & gRPC Functions ==========
  
  const loadHTTP2Frames = useCallback(async (proxyId: string, streamId?: number) => {
    try {
      setHttp2Loading(true);
      const data = await (mitmClient as any).getHTTP2Frames(proxyId, { stream_id: streamId });
      setHttp2Frames(data.frames || []);
    } catch (err: any) {
      console.error('Failed to load HTTP/2 frames:', err);
    } finally {
      setHttp2Loading(false);
    }
  }, []);

  const loadHTTP2Streams = useCallback(async (proxyId: string) => {
    try {
      const data = await (mitmClient as any).getHTTP2Streams(proxyId);
      setHttp2Streams(data.streams || []);
    } catch (err: any) {
      console.error('Failed to load HTTP/2 streams:', err);
    }
  }, []);

  const loadGRPCMessages = useCallback(async (proxyId: string, service?: string) => {
    try {
      const data = await (mitmClient as any).getGRPCMessages(proxyId, { service });
      setGrpcMessages(data.messages || []);
    } catch (err: any) {
      console.error('Failed to load gRPC messages:', err);
    }
  }, []);

  // Run test scenario
  const handleRunScenario = async (scenarioId: string) => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      setRunningScenario(true);
      const result = await (mitmClient as any).runTestScenario(selectedProxy, scenarioId);
      setScenarioResult(result);
      setSuccess(`Scenario "${result.scenario.name}" applied successfully!`);
      loadRules();
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to run scenario');
    } finally {
      setRunningScenario(false);
    }
  };

  // Natural Language Rule Creation
  const handleCreateNaturalLanguageRule = async () => {
    if (!nlRuleInput.trim()) {
      setError('Please enter a rule description');
      return;
    }
    try {
      setNlRuleLoading(true);
      setNlRuleResult(null);
      const result = await (mitmClient as any).createRuleFromNaturalLanguage(
        nlRuleInput,
        selectedProxy || undefined
      );
      setNlRuleResult(result);
      if (result.success) {
        setSuccess(result.applied 
          ? 'Rule created and applied to proxy!' 
          : 'Rule created successfully! Apply it to a proxy to use it.'
        );
        if (result.applied) {
          loadRules();
        }
      } else {
        setError(result.error || 'Failed to create rule from description');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to process natural language rule');
    } finally {
      setNlRuleLoading(false);
    }
  };

  // Apply AI-created rule to proxy
  const handleApplyNlRule = async () => {
    if (!nlRuleResult?.rule || !selectedProxy) {
      setError('Select a proxy and create a rule first');
      return;
    }
    try {
      setLoading(true);
      await mitmClient.addRule(selectedProxy, nlRuleResult.rule);
      setSuccess('Rule applied to proxy!');
      loadRules();
      setNlRuleResult(null);
      setNlRuleInput('');
    } catch (err: any) {
      setError(err.message || 'Failed to apply rule');
    } finally {
      setLoading(false);
    }
  };

  // Load AI Suggestions
  const handleLoadAiSuggestions = async () => {
    if (!selectedProxy) {
      setError('Please select a proxy first');
      return;
    }
    try {
      setAiSuggestionsLoading(true);
      const response = await (mitmClient as any).getAISuggestions(selectedProxy);
      setAiSuggestions(response.suggestions || []);
      setAiSuggestionsResponse(response);
      setShowAiSuggestions(true);
    } catch (err: any) {
      setError(err.message || 'Failed to get AI suggestions');
    } finally {
      setAiSuggestionsLoading(false);
    }
  };

  // Apply AI suggestion
  const handleApplyAiSuggestion = async (suggestion: AISuggestion) => {
    if (!selectedProxy || !suggestion.rule) {
      setError('No rule to apply');
      return;
    }
    try {
      setLoading(true);
      await mitmClient.addRule(selectedProxy, suggestion.rule);
      setSuccess(`Applied: ${suggestion.title}`);
      loadRules();
      // Remove applied suggestion from list
      setAiSuggestions(prev => prev.filter(s => s.id !== suggestion.id));
    } catch (err: any) {
      setError(err.message || 'Failed to apply suggestion');
    } finally {
      setLoading(false);
    }
  };

  // Create rule from suggestion's natural language
  const handleUseSuggestionNL = (suggestion: AISuggestion) => {
    setNlRuleInput(suggestion.natural_language);
    setShowNlRulePanel(true);
    setShowAiSuggestions(false);
  };

  // Load data when proxy selected
  useEffect(() => {
    if (selectedProxy) {
      setActiveSession(null);
      loadTraffic();
      loadRules();
      checkProxyHealth();
      loadWebSocketConnections();
      loadWebSocketStats();
      loadWebSocketRules();
    }
    setTrafficSearch('');
    setTrafficMethodFilter([]);
    setTrafficStatusFilter('all');
    setTrafficHostFilter('all');
    setTrafficModifiedOnly(false);
    setTrafficWithResponseOnly(false);
  }, [selectedProxy, loadTraffic, loadRules, loadWebSocketConnections, loadWebSocketStats, loadWebSocketRules]);

  useEffect(() => {
    if (!selectedTraffic) {
      setTrafficNotes('');
      setTrafficTagsInput('');
      return;
    }
    setTrafficNotes(selectedTraffic.notes || '');
    setTrafficTagsInput((selectedTraffic.tags || []).join(', '));
  }, [selectedTraffic]);

  useEffect(() => {
    if (!selectedTraffic) return;
    const updated = traffic.find(entry => entry.id === selectedTraffic.id);
    if (updated && updated !== selectedTraffic) {
      setSelectedTraffic(updated);
    }
  }, [traffic, selectedTraffic]);

  useEffect(() => {
    if (liveStreamEnabled) {
      setAutoRefresh(false);
    }
  }, [liveStreamEnabled]);

  // Auto-refresh traffic
  useEffect(() => {
    if (!autoRefresh || !selectedProxy || liveStreamEnabled || activeSession) return;
    const interval = setInterval(() => {
      loadTraffic();
      loadProxies();
    }, 2000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedProxy, liveStreamEnabled, activeSession, loadTraffic, loadProxies]);

  // Live stream via WebSocket
  useEffect(() => {
    if (!selectedProxy || !liveStreamEnabled || activeSession) {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setWsConnected(false);
      setWsError(null);
      return;
    }

    const ws = new WebSocket(buildWsUrl(selectedProxy));
    wsRef.current = ws;
    setWsConnected(false);
    setWsError(null);

    const handleInit = (message: any) => {
      const entries = Array.isArray(message.traffic)
        ? message.traffic
        : message.traffic?.entries || [];
      setTraffic(entries.map((entry: any) => normalizeTrafficEntry(entry)));
      if (Array.isArray(message.rules)) {
        setRules(message.rules);
      }
      if (message.status) {
        const status = message.status;
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return {
            ...proxy,
            listen_host: status.listen_host ?? proxy.listen_host,
            listen_port: status.listen_port ?? proxy.listen_port,
            target_host: status.target_host ?? proxy.target_host,
            target_port: status.target_port ?? proxy.target_port,
            mode: status.mode ?? proxy.mode,
            tls_enabled: status.tls_enabled ?? proxy.tls_enabled,
            running: status.running ?? proxy.running,
            stats: {
              ...proxy.stats,
              requests: status.stats?.requests ?? status.requests ?? proxy.stats.requests,
              responses: status.stats?.responses ?? status.responses ?? proxy.stats.responses,
              bytes_sent: status.stats?.bytes_sent ?? proxy.stats.bytes_sent,
              bytes_received: status.stats?.bytes_received ?? proxy.stats.bytes_received,
              errors: status.stats?.errors ?? proxy.stats.errors,
              rules_applied: status.stats?.rules_applied ?? proxy.stats.rules_applied,
            },
          };
        }));
      }
    };

    ws.onopen = () => setWsConnected(true);
    ws.onclose = () => setWsConnected(false);
    ws.onerror = () => {
      setWsConnected(false);
      setWsError('Live stream connection error');
    };
    ws.onmessage = (event) => {
      let message: any;
      try {
        message = JSON.parse(event.data);
      } catch {
        return;
      }
      if (message.type === 'init') {
        handleInit(message);
        return;
      }
      if (message.type === 'traffic' && message.entry) {
        const normalized = normalizeTrafficEntry(message.entry);
        setTraffic(prev => {
          const idx = prev.findIndex(entry => entry.id === normalized.id);
          if (idx === -1) {
            return [normalized, ...prev];
          }
          const existing = prev[idx];
          const merged = {
            ...existing,
            ...normalized,
            request: { ...existing.request, ...normalized.request },
            response: normalized.response ?? existing.response,
            tags: normalized.tags !== undefined ? normalized.tags : existing.tags,
            notes: normalized.notes !== undefined ? normalized.notes : existing.notes,
            rules_applied: normalized.rules_applied ?? existing.rules_applied,
            modified: normalized.modified ?? existing.modified,
            duration_ms: normalized.duration_ms ?? existing.duration_ms,
            timestamp: normalized.timestamp ?? existing.timestamp,
          };
          const next = [...prev];
          next[idx] = merged;
          return next;
        });
      } else if (message.type === 'stats' && message.stats) {
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return {
            ...proxy,
            stats: {
              ...proxy.stats,
              requests: message.stats.requests ?? proxy.stats.requests,
              responses: message.stats.responses ?? proxy.stats.responses,
              bytes_sent: message.stats.bytes_sent ?? proxy.stats.bytes_sent,
              bytes_received: message.stats.bytes_received ?? proxy.stats.bytes_received,
              errors: message.stats.errors ?? proxy.stats.errors,
              rules_applied: message.stats.rules_applied ?? proxy.stats.rules_applied,
            },
          };
        }));
      } else if (message.type === 'status') {
        if (message.deleted) {
          setProxies(prev => prev.filter(proxy => proxy.id !== selectedProxy));
          setSelectedProxy(null);
          setTraffic([]);
          setRules([]);
          return;
        }
        if (typeof message.running === 'boolean') {
          setProxies(prev => prev.map(proxy => {
            if (proxy.id !== selectedProxy) return proxy;
            return { ...proxy, running: message.running };
          }));
        }
      } else if (message.type === 'mode' && message.mode) {
        setProxies(prev => prev.map(proxy => {
          if (proxy.id !== selectedProxy) return proxy;
          return { ...proxy, mode: message.mode };
        }));
      } else if (message.type === 'rules') {
        loadRules();
      }
    };

    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping');
      }
    }, 10000);

    return () => {
      clearInterval(pingInterval);
      ws.close();
    };
  }, [selectedProxy, liveStreamEnabled, activeSession, buildWsUrl, normalizeTrafficEntry, loadRules]);

  // Create proxy
  const handleCreateProxy = async () => {
    try {
      setLoading(true);
      await mitmClient.createProxy(newProxy as any);
      setSuccess('Proxy created successfully');
      setNewProxyOpen(false);
      setNewProxy({
        proxy_id: '',
        listen_host: '127.0.0.1',
        listen_port: 8080,
        target_host: 'localhost',
        target_port: 80,
        mode: 'passthrough',
        tls_enabled: false,
      });
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to create proxy');
    } finally {
      setLoading(false);
    }
  };

  // Start/stop proxy
  const handleToggleProxy = async (proxyId: string, running: boolean) => {
    try {
      if (running) {
        await mitmClient.stopProxy(proxyId);
        setSuccess('Proxy stopped');
      } else {
        await mitmClient.startProxy(proxyId);
        setSuccess('Proxy started');
      }
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle proxy');
    }
  };

  // Delete proxy
  const handleDeleteProxy = async (proxyId: string) => {
    try {
      await mitmClient.deleteProxy(proxyId);
      setSuccess('Proxy deleted');
      if (selectedProxy === proxyId) {
        setSelectedProxy(null);
        setTraffic([]);
        setRules([]);
      }
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to delete proxy');
    }
  };

  // Change proxy mode
  const handleChangeMode = async (proxyId: string, mode: string) => {
    try {
      await mitmClient.setProxyMode(proxyId, mode);
      setSuccess(`Mode changed to ${mode}`);
      loadProxies();
    } catch (err: any) {
      setError(err.message || 'Failed to change mode');
    }
  };

  // Clear traffic
  const handleClearTraffic = async () => {
    if (!selectedProxy) return;
    try {
      await mitmClient.clearTraffic(selectedProxy);
      setTraffic([]);
      setSelectedTraffic(null);
      setSuccess('Traffic cleared');
    } catch (err: any) {
      setError(err.message || 'Failed to clear traffic');
    }
  };

  // Add rule
  const handleAddRule = async () => {
    if (!selectedProxy) return;
    try {
      const parseJson = (value: string, label: string) => {
        if (!value.trim()) return undefined;
        try {
          return JSON.parse(value);
        } catch {
          throw new Error(`${label} must be valid JSON`);
        }
      };

      const payload: Partial<InterceptionRule> = { ...newRule };
      const matchQuery = parseJson(ruleMatchQueryInput, 'Match query');
      if (matchQuery) payload.match_query = matchQuery;
      const modifyHeaders = parseJson(ruleModifyHeadersInput, 'Modify headers');
      if (modifyHeaders) payload.modify_headers = modifyHeaders;
      if (ruleRemoveHeadersInput.trim()) {
        payload.remove_headers = ruleRemoveHeadersInput
          .split(',')
          .map(header => header.trim())
          .filter(Boolean);
      }
      const bodyFindReplace = parseJson(ruleBodyFindReplaceInput, 'Body find/replace');
      if (bodyFindReplace) payload.body_find_replace = bodyFindReplace;
      const jsonPathEdits = parseJson(ruleJsonPathEditsInput, 'JSON path edits');
      if (jsonPathEdits) payload.json_path_edits = jsonPathEdits;

      await mitmClient.addRule(selectedProxy, payload);
      setSuccess('Rule added');
      setNewRuleOpen(false);
      setNewRule({
        name: '',
        enabled: true,
        match_direction: 'both',
        action: 'modify',
      });
      setRuleMatchQueryInput('');
      setRuleModifyHeadersInput('');
      setRuleRemoveHeadersInput('');
      setRuleBodyFindReplaceInput('');
      setRuleJsonPathEditsInput('');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to add rule');
    }
  };

  // Apply preset
  const handleApplyPreset = async (presetId: string) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.applyPreset(selectedProxy, presetId);
      setSuccess('Preset rule applied');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to apply preset');
    }
  };

  // Toggle rule
  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.toggleRule(selectedProxy, ruleId, enabled);
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule');
    }
  };

  const handleToggleRuleGroup = async (group: string, enabled: boolean) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.toggleRuleGroup(selectedProxy, group, enabled);
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to toggle rule group');
    }
  };

  // Delete rule
  const handleDeleteRule = async (ruleId: string) => {
    if (!selectedProxy) return;
    try {
      await mitmClient.removeRule(selectedProxy, ruleId);
      setSuccess('Rule deleted');
      loadRules();
    } catch (err: any) {
      setError(err.message || 'Failed to delete rule');
    }
  };

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSuccess('Copied to clipboard');
  };

  const openTrafficMenu = (event: React.MouseEvent<HTMLElement>, entry: TrafficEntry) => {
    setTrafficMenuAnchor(event.currentTarget);
    setTrafficMenuEntry(entry);
  };

  const closeTrafficMenu = () => {
    setTrafficMenuAnchor(null);
    setTrafficMenuEntry(null);
  };

  const getTrafficUrl = (entry: TrafficEntry) => {
    if (entry.request.url) return entry.request.url;
    const protocol = entry.request.protocol || (currentProxy?.tls_enabled ? 'https' : 'http');
    const host = entry.request.host || currentProxy?.target_host || 'localhost';
    return `${protocol}://${host}${entry.request.path || '/'}`;
  };

  const handleCopyAsCurl = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    const method = entry.request.method || 'GET';
    const headers = entry.request.headers || {};
    const body = entry.request.body || '';

    let command = `curl -i -X ${method} '${url}'`;
    Object.entries(headers).forEach(([key, value]) => {
      if (!key) return;
      command += ` -H '${key}: ${String(value).replace(/'/g, "\\'")}'`;
    });
    if (body) {
      command += ` --data-raw '${String(body).replace(/'/g, "\\'")}'`;
    }
    copyToClipboard(command);
    closeTrafficMenu();
  };

  const handleSendToApiTester = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    let baseUrl = url;
    let path = entry.request.path || '/';
    try {
      const parsed = new URL(url);
      baseUrl = `${parsed.protocol}//${parsed.host}`;
      path = `${parsed.pathname}${parsed.search}`;
    } catch {
      baseUrl = url;
    }
    const payload = {
      baseUrl,
      endpoints: [
        {
          url: path,
          method: entry.request.method || 'GET',
        },
      ],
    };
    localStorage.setItem(API_TESTER_HANDOFF_KEY, JSON.stringify(payload));
    navigate('/network/api-tester');
    closeTrafficMenu();
  };

  const handleSendToFuzzer = (entry: TrafficEntry) => {
    const url = getTrafficUrl(entry);
    const payload = {
      targetUrl: url,
      method: entry.request.method || 'GET',
      headers: entry.request.headers || {},
      body: entry.request.body || entry.request.body_text || '',
    };
    localStorage.setItem(FUZZER_HANDOFF_KEY, JSON.stringify(payload));
    navigate('/network/fuzzer');
    closeTrafficMenu();
  };

  const handleOpenReplay = (entry: TrafficEntry) => {
    setReplayEntry(entry);
    setReplayOverrides({
      method: entry.request.method || 'GET',
      path: entry.request.path || '/',
      body: entry.request.body || entry.request.body_text || '',
      addHeaders: '',
      removeHeaders: '',
      baseUrl: '',
      timeout: 20,
      verifyTls: false,
    });
    setReplayOpen(true);
    closeTrafficMenu();
  };

  const handleReplayRequest = async () => {
    if (!selectedProxy || !replayEntry) return;
    try {
      setReplayLoading(true);
      let addHeaders: Record<string, string> | undefined;
      if (replayOverrides.addHeaders.trim()) {
        try {
          addHeaders = JSON.parse(replayOverrides.addHeaders);
        } catch {
          setError('Add headers must be valid JSON');
          return;
        }
      }
      const removeHeaders = replayOverrides.removeHeaders
        .split(',')
        .map(header => header.trim())
        .filter(Boolean);
      const response = await mitmClient.replayTrafficEntry(selectedProxy, replayEntry.id, {
        method: replayOverrides.method || undefined,
        path: replayOverrides.path || undefined,
        body: replayOverrides.body,
        add_headers: addHeaders,
        remove_headers: removeHeaders.length ? removeHeaders : undefined,
        base_url: replayOverrides.baseUrl || undefined,
        timeout: replayOverrides.timeout || undefined,
        verify_tls: replayOverrides.verifyTls,
      });
      if (response?.entry) {
        const normalized = normalizeTrafficEntry(response.entry);
        setTraffic(prev => [normalized, ...prev]);
      } else {
        loadTraffic();
      }
      setSuccess('Replay complete');
      setReplayOpen(false);
    } catch (err: any) {
      setError(err.message || 'Failed to replay request');
    } finally {
      setReplayLoading(false);
    }
  };

  const handleCreateRuleFromEntry = (entry: TrafficEntry, action: 'modify' | 'drop' = 'modify') => {
    setNewRule({
      name: `${action === 'drop' ? 'Block' : 'Match'} ${entry.request.method} ${entry.request.path}`,
      enabled: true,
      match_direction: 'request',
      match_host: entry.request.host,
      match_path: entry.request.path,
      match_method: entry.request.method,
      action,
    });
    setRuleMatchQueryInput('');
    setRuleModifyHeadersInput('');
    setRuleRemoveHeadersInput('');
    setRuleBodyFindReplaceInput('');
    setRuleJsonPathEditsInput('');
    setNewRuleOpen(true);
    closeTrafficMenu();
  };

  const handleSaveTrafficMeta = async () => {
    if (!selectedProxy || !selectedTraffic) return;
    try {
      setSavingTrafficMeta(true);
      const tags = trafficTagsInput
        .split(',')
        .map(tag => tag.trim())
        .filter(Boolean);
      const updated = await mitmClient.updateTrafficEntry(
        selectedProxy,
        selectedTraffic.id,
        { notes: trafficNotes, tags }
      );
      const normalized = normalizeTrafficEntry(updated);
      setSelectedTraffic(normalized);
      setTraffic(prev => prev.map(entry => entry.id === normalized.id ? normalized : entry));
      setSuccess('Notes saved');
    } catch (err: any) {
      setError(err.message || 'Failed to save notes');
    } finally {
      setSavingTrafficMeta(false);
    }
  };

  // Load guided setup
  const loadGuidedSetup = async () => {
    try {
      setLoadingGuide(true);
      const data = await mitmClient.getGuidedSetup();
      setGuidedSetup(data);
    } catch (err: any) {
      setError('Failed to load guided setup');
    } finally {
      setLoadingGuide(false);
    }
  };

  // Open wizard
  const handleOpenWizard = async () => {
    if (!guidedSetup) {
      await loadGuidedSetup();
    }
    setWizardOpen(true);
    setWizardStep(0);
  };

  // Analyze traffic with AI
  const handleAnalyzeTraffic = async () => {
    if (!selectedProxy) return;
    try {
      setAnalyzingTraffic(true);
      const result = await mitmClient.analyzeTraffic(selectedProxy);
      setAnalysisResult(result);
      setShowAnalysis(true);
      setSuccess('Traffic analysis complete');
    } catch (err: any) {
      setError(err.message || 'Failed to analyze traffic');
    } finally {
      setAnalyzingTraffic(false);
    }
  };

  // Export report
  const handleExportReport = async (format: 'markdown' | 'pdf' | 'docx') => {
    if (!selectedProxy) return;
    try {
      setExporting(true);
      setExportAnchorEl(null);
      const blob = await mitmClient.exportReport(selectedProxy, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'markdown' ? 'md' : format;
      a.download = `mitm-report-${selectedProxy}-${new Date().toISOString().split('T')[0]}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess(`Report exported as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || `Failed to export ${format} report`);
    } finally {
      setExporting(false);
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'error';
      case 'high': return 'error';
      case 'medium': return 'warning';
      case 'low': return 'info';
      default: return 'default';
    }
  };

  // Get risk level color
  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical': return '#d32f2f';
      case 'high': return '#f44336';
      case 'medium': return '#ff9800';
      case 'low': return '#4caf50';
      default: return '#9e9e9e';
    }
  };

  // Export traffic
  const exportTraffic = async (format: 'json' | 'pcap') => {
    if (!selectedProxy) return;
    try {
      setTrafficExporting(true);
      setTrafficExportAnchorEl(null);
      let blob: Blob | null = null;
      if (activeSession) {
        if (format !== 'json') {
          setError('PCAP export is only available for live traffic');
          return;
        }
        const data = JSON.stringify(traffic, null, 2);
        blob = new Blob([data], { type: 'application/json' });
      } else {
        blob = await mitmClient.exportTraffic(selectedProxy, format);
      }
      if (!blob) return;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const ext = format === 'json' ? 'json' : 'pcap';
      const sessionSuffix = activeSession ? `-session-${activeSession.id}` : '';
      a.download = `mitm-traffic-${selectedProxy}${sessionSuffix}-${new Date().toISOString().split('T')[0]}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess(`Traffic exported as ${format.toUpperCase()}`);
    } catch (err: any) {
      setError(err.message || `Failed to export ${format.toUpperCase()} traffic`);
    } finally {
      setTrafficExporting(false);
    }
  };

  // Get selected proxy details
  const currentProxy = proxies.find(p => p.id === selectedProxy);

  const uniqueHosts = useMemo(() => {
    const hosts = new Set<string>();
    traffic.forEach(entry => {
      if (entry.request.host) {
        hosts.add(entry.request.host);
      }
    });
    return Array.from(hosts).sort();
  }, [traffic]);

  const uniqueMethods = useMemo(() => {
    const methods = new Set<string>();
    traffic.forEach(entry => {
      if (entry.request.method) {
        methods.add(entry.request.method);
      }
    });
    return Array.from(methods).sort();
  }, [traffic]);

  const trafficSummary = useMemo(() => {
    let modifiedCount = 0;
    let errorCount = 0;
    let durationTotal = 0;
    let durationSamples = 0;
    const hosts = new Set<string>();

    traffic.forEach(entry => {
      if (entry.modified) modifiedCount += 1;
      if (entry.request.host) hosts.add(entry.request.host);
      if (entry.response?.status_code && entry.response.status_code >= 400) {
        errorCount += 1;
      }
      if (typeof entry.duration_ms === 'number' && entry.duration_ms > 0) {
        durationTotal += entry.duration_ms;
        durationSamples += 1;
      }
    });

    return {
      total: traffic.length,
      modified: modifiedCount,
      errors: errorCount,
      hosts: hosts.size,
      avgDuration: durationSamples ? Math.round(durationTotal / durationSamples) : 0,
    };
  }, [traffic]);

  const filteredTraffic = useMemo(() => {
    const search = trafficSearch.trim().toLowerCase();
    const hasMethodFilter = trafficMethodFilter.length > 0;
    const hasHostFilter = trafficHostFilter !== 'all';

    const filtered = traffic.filter(entry => {
      if (trafficModifiedOnly && !entry.modified) return false;
      if (trafficWithResponseOnly && !entry.response) return false;
      if (hasMethodFilter && !trafficMethodFilter.includes(entry.request.method)) return false;
      if (hasHostFilter && entry.request.host !== trafficHostFilter) return false;

      if (trafficStatusFilter !== 'all') {
        if (trafficStatusFilter === 'pending') {
          if (entry.response) return false;
        } else {
          const statusCode = entry.response?.status_code;
          if (!statusCode) return false;
          const statusGroup = `${Math.floor(statusCode / 100)}xx`;
          if (statusGroup !== trafficStatusFilter) return false;
        }
      }

      if (!search) return true;

      const haystack = [
        entry.request.method,
        entry.request.path,
        entry.request.host,
        entry.request.url,
        entry.response?.status_code?.toString(),
        entry.response?.status_text,
        entry.notes,
        (entry.tags || []).join(' '),
        (entry.rules_applied || []).join(' '),
        JSON.stringify(entry.request.headers),
        entry.request.body,
        JSON.stringify(entry.response?.headers || {}),
        entry.response?.body,
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();

      return haystack.includes(search);
    });

    const sorted = [...filtered].sort((a, b) => {
      const aTime = new Date(a.timestamp).getTime();
      const bTime = new Date(b.timestamp).getTime();
      return trafficSort === 'newest' ? bTime - aTime : aTime - bTime;
    });

    return sorted;
  }, [
    traffic,
    trafficSearch,
    trafficMethodFilter,
    trafficStatusFilter,
    trafficHostFilter,
    trafficModifiedOnly,
    trafficWithResponseOnly,
    trafficSort,
  ]);

  const hasActiveTrafficFilters =
    trafficSearch.trim().length > 0 ||
    trafficMethodFilter.length > 0 ||
    trafficStatusFilter !== 'all' ||
    trafficHostFilter !== 'all' ||
    trafficModifiedOnly ||
    trafficWithResponseOnly;

  const ruleGroups = useMemo(() => {
    const groups: Record<string, { total: number; enabled: number }> = {};
    rules.forEach(rule => {
      if (!rule.group) return;
      const name = rule.group;
      if (!groups[name]) {
        groups[name] = { total: 0, enabled: 0 };
      }
      groups[name].total += 1;
      if (rule.enabled) groups[name].enabled += 1;
    });
    return Object.entries(groups).map(([name, info]) => ({
      name,
      total: info.total,
      enabledCount: info.enabled,
      allEnabled: info.enabled === info.total,
    }));
  }, [rules]);

  // Format bytes
  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  // Get health status color
  const getHealthStatusColor = (status: string) => {
    switch (status) {
      case 'pass': return 'success';
      case 'fail': return 'error';
      case 'warning': return 'warning';
      default: return 'info';
    }
  };

  // Get difficulty color
  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'beginner': return 'success';
      case 'intermediate': return 'warning';
      case 'advanced': return 'error';
      default: return 'default';
    }
  };

  // Tutorial steps for interactive walkthrough
  const tutorialSteps = [
    { target: 'create-proxy', title: 'Create Your First Proxy', description: 'Start by creating a new proxy instance. Click "New Proxy" to begin.' },
    { target: 'proxy-config', title: 'Configure Proxy Settings', description: 'Enter a unique name and set target address.' },
    { target: 'start-proxy', title: 'Start the Proxy', description: 'Click the play button to start intercepting traffic.' },
    { target: 'test-scenarios', title: 'Try a Test Scenario', description: 'Use pre-built scenarios to learn security testing.' },
    { target: 'traffic-log', title: 'View Traffic', description: 'See intercepted requests in real-time.' },
    { target: 'analyze', title: 'Analyze with AI', description: 'Let AI find security issues automatically.' },
  ];

  // Traffic Flow Visualization Component
  const TrafficFlowVisualization = () => {
    const isProxyRunning = currentProxy?.running;
    const hasTraffic = traffic.length > 0;
    
    return (
      <Paper 
        sx={{ 
          p: 2, 
          mb: 2, 
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)`,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
          Traffic Flow
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 2 }}>
          {/* Client */}
          <Box sx={{ textAlign: 'center' }}>
            <Avatar sx={{ bgcolor: 'info.main', width: 56, height: 56, mb: 1, mx: 'auto' }}>
              <ClientIcon />
            </Avatar>
            <Typography variant="caption" display="block">Client App</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              Your Browser/App
            </Typography>
          </Box>

          {/* Arrow 1 */}
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              {isProxyRunning && hasTraffic && (
                <Zoom in>
                  <DotIcon sx={{ color: 'success.main', fontSize: 12, animation: 'pulse 1s infinite', mr: -1 }} />
                </Zoom>
              )}
              <ArrowRightIcon sx={{ color: isProxyRunning ? 'success.main' : 'text.disabled', fontSize: 32 }} />
            </Box>
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'} sx={{ fontSize: '0.6rem' }}>
              {isProxyRunning ? 'Requests →' : 'Configure proxy'}
            </Typography>
          </Box>

          {/* Proxy */}
          <Box sx={{ textAlign: 'center' }}>
            <Badge
              badgeContent={rules.length}
              color="warning"
              overlap="circular"
              anchorOrigin={{ vertical: 'top', horizontal: 'right' }}
            >
              <Avatar 
                sx={{ 
                  bgcolor: isProxyRunning ? 'warning.main' : 'grey.500', 
                  width: 64, 
                  height: 64, 
                  mb: 1, 
                  mx: 'auto',
                  border: `3px solid ${isProxyRunning ? theme.palette.success.main : theme.palette.grey[600]}`,
                  animation: isProxyRunning ? 'pulse 2s infinite' : 'none',
                }}
              >
                <ProxyIcon />
              </Avatar>
            </Badge>
            <Typography variant="caption" display="block" fontWeight="bold">MITM Proxy</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              {currentProxy ? `${currentProxy.listen_host}:${currentProxy.listen_port}` : 'Not selected'}
            </Typography>
            {currentProxy && (
              <Chip 
                label={currentProxy.mode} 
                size="small" 
                sx={{ mt: 0.5, fontSize: '0.6rem', height: 18 }}
                color={currentProxy.mode === 'auto_modify' ? 'warning' : 'default'}
              />
            )}
          </Box>

          {/* Arrow 2 */}
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <Box sx={{ display: 'flex', alignItems: 'center' }}>
              <ArrowRightIcon sx={{ color: isProxyRunning ? 'success.main' : 'text.disabled', fontSize: 32 }} />
              {isProxyRunning && hasTraffic && (
                <Zoom in>
                  <DotIcon sx={{ color: 'success.main', fontSize: 12, animation: 'pulse 1s infinite', ml: -1 }} />
                </Zoom>
              )}
            </Box>
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'} sx={{ fontSize: '0.6rem' }}>
              {isProxyRunning ? '→ Forwarded' : ''}
            </Typography>
          </Box>

          {/* Server */}
          <Box sx={{ textAlign: 'center' }}>
            <Avatar sx={{ bgcolor: 'secondary.main', width: 56, height: 56, mb: 1, mx: 'auto' }}>
              <ServerIcon />
            </Avatar>
            <Typography variant="caption" display="block">Target Server</Typography>
            <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem' }}>
              {currentProxy ? `${currentProxy.target_host}:${currentProxy.target_port}` : 'Not configured'}
            </Typography>
          </Box>
        </Box>

        {/* Status bar */}
        <Box sx={{ mt: 2, display: 'flex', justifyContent: 'center', gap: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {isProxyRunning ? (
              <WifiIcon sx={{ color: 'success.main', fontSize: 16 }} />
            ) : (
              <WifiOffIcon sx={{ color: 'text.disabled', fontSize: 16 }} />
            )}
            <Typography variant="caption" color={isProxyRunning ? 'success.main' : 'text.secondary'}>
              {isProxyRunning ? 'Connected' : 'Disconnected'}
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <HttpIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Typography variant="caption" color="text.secondary">
              {traffic.length} requests captured
            </Typography>
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <RuleIcon sx={{ fontSize: 16, color: 'text.secondary' }} />
            <Typography variant="caption" color="text.secondary">
              {rules.length} rules active
            </Typography>
          </Box>
        </Box>
      </Paper>
    );
  };

  // Health Check Component
  const HealthCheckPanel = () => {
    if (!proxyHealth) return null;
    
    return (
      <Paper sx={{ p: 2, mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Avatar 
              sx={{ 
                width: 32, 
                height: 32, 
                bgcolor: proxyHealth.status === 'healthy' ? 'success.main' : 
                         proxyHealth.status === 'warning' ? 'warning.main' : 'error.main' 
              }}
            >
              {proxyHealth.status === 'healthy' ? <CheckIcon sx={{ fontSize: 18 }} /> :
               proxyHealth.status === 'warning' ? <WarningIcon sx={{ fontSize: 18 }} /> :
               <ErrorIcon sx={{ fontSize: 18 }} />}
            </Avatar>
            <Box>
              <Typography variant="subtitle2">
                Health: {proxyHealth.status.toUpperCase()}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {proxyHealth.checks.filter(c => c.status === 'pass').length}/{proxyHealth.checks.length} checks passed
              </Typography>
            </Box>
          </Box>
          <IconButton size="small" onClick={checkProxyHealth} disabled={checkingHealth}>
            {checkingHealth ? <CircularProgress size={16} /> : <RefreshIcon fontSize="small" />}
          </IconButton>
        </Box>
        
        <Grid container spacing={1}>
          {proxyHealth.checks.map((check, idx) => (
            <Grid item xs={6} key={idx}>
              <Box 
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 0.5,
                  p: 0.5,
                  borderRadius: 1,
                  bgcolor: alpha(
                    check.status === 'pass' ? theme.palette.success.main :
                    check.status === 'fail' ? theme.palette.error.main : 
                    theme.palette.info.main, 
                    0.1
                  ),
                }}
              >
                {check.status === 'pass' && <CheckIcon sx={{ fontSize: 14, color: 'success.main' }} />}
                {check.status === 'fail' && <CancelIcon sx={{ fontSize: 14, color: 'error.main' }} />}
                {check.status === 'info' && <InfoIcon sx={{ fontSize: 14, color: 'info.main' }} />}
                {check.status === 'warning' && <WarningIcon sx={{ fontSize: 14, color: 'warning.main' }} />}
                <Typography variant="caption" sx={{ fontSize: '0.7rem' }}>{check.name}</Typography>
              </Box>
            </Grid>
          ))}
        </Grid>

        {proxyHealth.recommendations.length > 0 && (
          <Alert severity="info" sx={{ mt: 2, py: 0 }} icon={<TipIcon sx={{ fontSize: 18 }} />}>
            <Typography variant="caption">
              {proxyHealth.recommendations[0]}
            </Typography>
          </Alert>
        )}
      </Paper>
    );
  };

  return (
    <Box sx={{ p: 3, height: '100vh', display: 'flex', flexDirection: 'column' }}>
      {/* Beginner Welcome Banner */}
      <Collapse in={showBeginnerBanner && proxies.length === 0}>
        <Alert 
          severity="info" 
          sx={{ mb: 2 }}
          icon={<ScienceIcon />}
          action={
            <IconButton size="small" onClick={() => setShowBeginnerBanner(false)}>
              <CloseIcon fontSize="small" />
            </IconButton>
          }
        >
          <AlertTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography fontWeight="bold">Welcome to the MITM Workbench! 👋</Typography>
            <Chip label="Beginner Friendly" size="small" color="success" />
          </AlertTitle>
          <Typography variant="body2" sx={{ mb: 1 }}>
            Learn to intercept and analyze network traffic like a security professional. No experience required!
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Button size="small" variant="contained" startIcon={<TutorialIcon />} onClick={handleOpenWizard}>
              Start Tutorial
            </Button>
            <Button size="small" variant="outlined" startIcon={<LearnIcon />} href="/learn/mitm">
              Read the Guide
            </Button>
            <Button size="small" variant="outlined" startIcon={<ScienceIcon />} onClick={() => setScenarioDialogOpen(true)}>
              Try a Test Scenario
            </Button>
          </Box>
        </Alert>
      </Collapse>

      {/* Header */}
      <Box sx={{ mb: 3, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          {projectId && (
            <Tooltip title={`Back to ${projectName || 'Project'}`}>
              <IconButton
                onClick={() => navigate(`/projects/${projectId}`)}
                sx={{ mr: 1 }}
              >
                <BackIcon />
              </IconButton>
            </Tooltip>
          )}
          <SwapIcon sx={{ fontSize: 40, color: 'warning.main' }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Man-in-the-Middle Workbench
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Intercept, inspect, and modify HTTP/HTTPS traffic between components
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Pre-built security test scenarios">
            <Button
              variant="outlined"
              color="warning"
              startIcon={<ScienceIcon />}
              onClick={() => setScenarioDialogOpen(true)}
            >
              Test Scenarios
            </Button>
          </Tooltip>
          <Tooltip title="Step-by-step guide for beginners">
            <Button
              variant="outlined"
              color="info"
              startIcon={<TutorialIcon />}
              onClick={handleOpenWizard}
            >
              Getting Started
            </Button>
          </Tooltip>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setNewProxyOpen(true)}
          >
            New Proxy
          </Button>
        </Box>
      </Box>

      {/* Main content */}
      <Grid container spacing={2} sx={{ flex: 1, minHeight: 0 }}>
        {/* Proxy list sidebar */}
        <Grid item xs={12} md={3}>
          <Paper sx={{ height: '100%', overflow: 'auto' }}>
            <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider' }}>
              <Typography variant="h6">Proxy Instances</Typography>
            </Box>
            <List>
              {proxies.length === 0 ? (
                <ListItem>
                  <ListItemText
                    primary="No proxies configured"
                    secondary="Create a new proxy to get started"
                  />
                </ListItem>
              ) : (
                proxies.map((proxy) => (
                  <ListItem
                    key={proxy.id}
                    button
                    selected={selectedProxy === proxy.id}
                    onClick={() => setSelectedProxy(proxy.id)}
                    sx={{
                      borderLeft: selectedProxy === proxy.id ? 4 : 0,
                      borderColor: 'primary.main',
                    }}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          {proxy.tls_enabled ? <LockIcon fontSize="small" /> : <LockOpenIcon fontSize="small" />}
                          <Typography variant="subtitle2">{proxy.id}</Typography>
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 0.5 }}>
                          <Typography variant="caption" display="block">
                            {proxy.listen_host}:{proxy.listen_port} → {proxy.target_host}:{proxy.target_port}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                            <Chip
                              label={proxy.running ? 'Running' : 'Stopped'}
                              size="small"
                              color={proxy.running ? 'success' : 'default'}
                            />
                            <Chip
                              label={proxy.mode}
                              size="small"
                              color={
                                proxy.mode === 'intercept' ? 'warning' :
                                proxy.mode === 'auto_modify' ? 'info' : 'default'
                              }
                            />
                          </Box>
                        </Box>
                      }
                    />
                    <ListItemSecondaryAction>
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleToggleProxy(proxy.id, proxy.running);
                        }}
                      >
                        {proxy.running ? <StopIcon color="error" /> : <PlayIcon color="success" />}
                      </IconButton>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))
              )}
            </List>
          </Paper>
        </Grid>

        {/* Main workspace */}
        <Grid item xs={12} md={9}>
          {/* Traffic Flow Visualization - always visible when proxy selected */}
          {selectedProxy && currentProxy && <TrafficFlowVisualization />}
          
          {/* Health Check Panel - when proxy selected */}
          {selectedProxy && currentProxy && <HealthCheckPanel />}

          {/* AI-Powered Natural Language Rule Creation Panel */}
          {selectedProxy && currentProxy && (
            <Paper sx={{ p: 2, mb: 2, background: `linear-gradient(135deg, ${alpha(theme.palette.secondary.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)` }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <AIIcon color="secondary" />
                  <Typography variant="subtitle1" fontWeight="bold">
                    Natural Language Rule Creation
                  </Typography>
                  <Chip label="AI-Powered" size="small" color="secondary" variant="outlined" />
                </Box>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title="Get AI suggestions based on captured traffic">
                    <Button
                      variant="outlined"
                      size="small"
                      startIcon={aiSuggestionsLoading ? <CircularProgress size={16} /> : <IdeaIcon />}
                      onClick={handleLoadAiSuggestions}
                      disabled={aiSuggestionsLoading || traffic.length === 0}
                    >
                      AI Suggestions
                    </Button>
                  </Tooltip>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Describe what you want to do in plain English, and AI will create the rule for you.
              </Typography>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
                <TextField
                  fullWidth
                  variant="outlined"
                  placeholder="e.g., &quot;Block all requests to analytics.google.com&quot; or &quot;Add a 2 second delay to all API responses&quot; or &quot;Remove the Authorization header&quot;"
                  value={nlRuleInput}
                  onChange={(e) => setNlRuleInput(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && handleCreateNaturalLanguageRule()}
                  disabled={nlRuleLoading}
                  multiline
                  maxRows={2}
                  InputProps={{
                    startAdornment: <CodeIcon sx={{ mr: 1, color: 'text.secondary' }} />,
                  }}
                />
                <Button
                  variant="contained"
                  color="secondary"
                  startIcon={nlRuleLoading ? <CircularProgress size={20} color="inherit" /> : <AIIcon />}
                  onClick={handleCreateNaturalLanguageRule}
                  disabled={nlRuleLoading || !nlRuleInput.trim()}
                  sx={{ minWidth: 140, height: 56 }}
                >
                  {nlRuleLoading ? 'Creating...' : 'Create Rule'}
                </Button>
              </Box>
              
              {/* NL Rule Result */}
              {nlRuleResult && (
                <Fade in>
                  <Box sx={{ mt: 2, p: 2, bgcolor: nlRuleResult.success ? alpha(theme.palette.success.main, 0.1) : alpha(theme.palette.error.main, 0.1), borderRadius: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
                      {nlRuleResult.success ? <SuccessIcon color="success" /> : <ErrorIcon color="error" />}
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle2" fontWeight="bold">
                          {nlRuleResult.success ? 'Rule Created!' : 'Could not create rule'}
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                          {nlRuleResult.interpretation}
                        </Typography>
                        {nlRuleResult.rule && (
                          <Box sx={{ mt: 1, p: 1, bgcolor: 'background.paper', borderRadius: 1, fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            <Typography variant="caption" color="text.secondary">Generated Rule:</Typography>
                            <Typography variant="body2">
                              Pattern: <code>{(nlRuleResult.rule as any)?.pattern || (nlRuleResult.rule as any)?.match_host || '.*'}</code>
                            </Typography>
                            <Typography variant="body2">
                              Action: <Chip label={(nlRuleResult.rule as any)?.action || 'modify'} size="small" />
                            </Typography>
                          </Box>
                        )}
                        {nlRuleResult.success && !nlRuleResult.applied && nlRuleResult.rule && (
                          <Button
                            variant="contained"
                            size="small"
                            color="success"
                            startIcon={<AddIcon />}
                            onClick={handleApplyNlRule}
                            sx={{ mt: 1 }}
                          >
                            Apply to Proxy
                          </Button>
                        )}
                        {nlRuleResult.applied && (
                          <Chip 
                            icon={<CheckIcon />} 
                            label="Applied to proxy" 
                            color="success" 
                            size="small"
                            sx={{ mt: 1 }}
                          />
                        )}
                      </Box>
                      <IconButton size="small" onClick={() => setNlRuleResult(null)}>
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    </Box>
                  </Box>
                </Fade>
              )}
              
              {/* Example suggestions */}
              <Box sx={{ mt: 2 }}>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <TipIcon fontSize="small" /> Try these examples:
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 1 }}>
                  {[
                    'Block all analytics tracking',
                    'Add 500ms delay to API calls',
                    'Remove cookies from all requests',
                    'Replace all prices with $0.00',
                    'Add X-Debug-Mode: true header'
                  ].map((example) => (
                    <Chip
                      key={example}
                      label={example}
                      size="small"
                      variant="outlined"
                      onClick={() => setNlRuleInput(example)}
                      sx={{ cursor: 'pointer', '&:hover': { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                    />
                  ))}
                </Box>
              </Box>
            </Paper>
          )}

          {/* AI Suggestions Panel */}
          <Collapse in={showAiSuggestions && aiSuggestions.length > 0}>
            <Paper sx={{ p: 2, mb: 2, border: `2px solid ${theme.palette.info.main}`, borderRadius: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <IdeaIcon color="info" />
                  <Typography variant="subtitle1" fontWeight="bold">
                    AI Suggestions Based on Your Traffic
                  </Typography>
                  <Chip 
                    label={`${aiSuggestions.length} suggestions`} 
                    size="small" 
                    color="info"
                  />
                </Box>
                <IconButton size="small" onClick={() => setShowAiSuggestions(false)}>
                  <CloseIcon />
                </IconButton>
              </Box>
              
              {aiSuggestionsResponse?.traffic_summary && (
                <Box sx={{ mb: 2, p: 1.5, bgcolor: alpha(theme.palette.info.main, 0.05), borderRadius: 1 }}>
                  <Typography variant="caption" color="text.secondary" gutterBottom>
                    Traffic Analysis Summary:
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 0.5 }}>
                    <Chip label={`${aiSuggestionsResponse.traffic_summary.total_requests || 0} requests`} size="small" />
                    {aiSuggestionsResponse.traffic_summary.auth_detected && (
                      <Chip label="Auth Detected" size="small" color="warning" icon={<LockIcon />} />
                    )}
                    {aiSuggestionsResponse.traffic_summary.json_apis && (
                      <Chip label="JSON APIs" size="small" color="primary" icon={<CodeIcon />} />
                    )}
                    {aiSuggestionsResponse.traffic_summary.has_cookies && (
                      <Chip label="Cookies Present" size="small" color="secondary" />
                    )}
                  </Box>
                </Box>
              )}

              <Grid container spacing={2}>
                {aiSuggestions.map((suggestion) => (
                  <Grid item xs={12} md={6} key={suggestion.id}>
                    <Card 
                      variant="outlined"
                      sx={{ 
                        height: '100%',
                        borderColor: suggestion.priority === 'high' 
                          ? theme.palette.error.main 
                          : suggestion.priority === 'medium' 
                            ? theme.palette.warning.main 
                            : theme.palette.grey[300],
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        '&:hover': { transform: 'translateY(-2px)', boxShadow: 2 }
                      }}
                    >
                      <CardContent sx={{ pb: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1 }}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {suggestion.category === 'security' && <ShieldIcon color="error" fontSize="small" />}
                            {suggestion.category === 'performance' && <SpeedIcon color="warning" fontSize="small" />}
                            {suggestion.category === 'debug' && <DebugIcon color="info" fontSize="small" />}
                            {suggestion.category === 'learning' && <TutorialIcon color="success" fontSize="small" />}
                            <Typography variant="subtitle2" fontWeight="bold">
                              {suggestion.title}
                            </Typography>
                          </Box>
                          <Chip 
                            label={suggestion.priority} 
                            size="small"
                            color={suggestion.priority === 'high' ? 'error' : suggestion.priority === 'medium' ? 'warning' : 'default'}
                          />
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                          {suggestion.description}
                        </Typography>
                        {suggestion.natural_language && (
                          <Typography variant="caption" sx={{ fontStyle: 'italic', display: 'block', mb: 1 }}>
                            "{suggestion.natural_language}"
                          </Typography>
                        )}
                      </CardContent>
                      <CardActions sx={{ justifyContent: 'flex-end', pt: 0 }}>
                        {suggestion.natural_language && (
                          <Tooltip title="Use this as natural language input">
                            <Button 
                              size="small" 
                              onClick={() => handleUseSuggestionNL(suggestion)}
                            >
                              Use Text
                            </Button>
                          </Tooltip>
                        )}
                        {suggestion.rule && (
                          <Button 
                            size="small" 
                            variant="contained" 
                            color="primary"
                            startIcon={<AddIcon />}
                            onClick={() => handleApplyAiSuggestion(suggestion)}
                          >
                            Quick Apply
                          </Button>
                        )}
                      </CardActions>
                    </Card>
                  </Grid>
                ))}
              </Grid>
            </Paper>
          </Collapse>

          {selectedProxy && currentProxy ? (
            <Paper sx={{ height: 'calc(100% - 200px)', display: 'flex', flexDirection: 'column' }}>
              {/* Proxy header */}
              <Box sx={{ p: 2, borderBottom: 1, borderColor: 'divider', bgcolor: 'background.default' }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Box>
                    <Typography variant="h6">{currentProxy.id}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {currentProxy.listen_host}:{currentProxy.listen_port} → {currentProxy.target_host}:{currentProxy.target_port}
                    </Typography>
                  </Box>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <Tooltip title="AI-powered security analysis">
                      <Button
                        variant="outlined"
                        color="secondary"
                        startIcon={analyzingTraffic ? <CircularProgress size={20} /> : <AIIcon />}
                        onClick={handleAnalyzeTraffic}
                        disabled={analyzingTraffic || traffic.length === 0}
                        size="small"
                      >
                        Analyze
                      </Button>
                    </Tooltip>
                    <Tooltip title="Export report">
                      <Button
                        variant="outlined"
                        startIcon={exporting ? <CircularProgress size={20} /> : <DownloadIcon />}
                        onClick={(e) => setExportAnchorEl(e.currentTarget)}
                        disabled={exporting}
                        size="small"
                      >
                        Export
                      </Button>
                    </Tooltip>
                    <Menu
                      anchorEl={exportAnchorEl}
                      open={Boolean(exportAnchorEl)}
                      onClose={() => setExportAnchorEl(null)}
                    >
                      <MenuItem onClick={() => handleExportReport('markdown')}>
                        <ListItemIcon><MarkdownIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>Markdown (.md)</ListItemText>
                      </MenuItem>
                      <MenuItem onClick={() => handleExportReport('pdf')}>
                        <ListItemIcon><PdfIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>PDF Document</ListItemText>
                      </MenuItem>
                      <MenuItem onClick={() => handleExportReport('docx')}>
                        <ListItemIcon><WordIcon fontSize="small" /></ListItemIcon>
                        <ListItemText>Word Document (.docx)</ListItemText>
                      </MenuItem>
                    </Menu>
                    <FormControl size="small" sx={{ minWidth: 140 }}>
                      <InputLabel>Mode</InputLabel>
                      <Select
                        value={currentProxy.mode}
                        label="Mode"
                        onChange={(e) => handleChangeMode(currentProxy.id, e.target.value)}
                      >
                        <MenuItem value="passthrough">Passthrough</MenuItem>
                        <MenuItem value="intercept">Intercept</MenuItem>
                        <MenuItem value="auto_modify">Auto Modify</MenuItem>
                      </Select>
                    </FormControl>
                    <Button
                      variant={currentProxy.running ? 'outlined' : 'contained'}
                      color={currentProxy.running ? 'error' : 'success'}
                      startIcon={currentProxy.running ? <StopIcon /> : <PlayIcon />}
                      onClick={() => handleToggleProxy(currentProxy.id, currentProxy.running)}
                    >
                      {currentProxy.running ? 'Stop' : 'Start'}
                    </Button>
                    <IconButton color="error" onClick={() => handleDeleteProxy(currentProxy.id)}>
                      <DeleteIcon />
                    </IconButton>
                  </Box>
                </Box>

                {/* Stats */}
                <Box sx={{ display: 'flex', gap: 3, mt: 2 }}>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Requests</Typography>
                    <Typography variant="h6">{currentProxy.stats.requests}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Responses</Typography>
                    <Typography variant="h6">{currentProxy.stats.responses}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Sent</Typography>
                    <Typography variant="h6">{formatBytes(currentProxy.stats.bytes_sent)}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Received</Typography>
                    <Typography variant="h6">{formatBytes(currentProxy.stats.bytes_received)}</Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Errors</Typography>
                    <Typography variant="h6" color={currentProxy.stats.errors > 0 ? 'error.main' : 'inherit'}>
                      {currentProxy.stats.errors}
                    </Typography>
                  </Box>
                  <Box>
                    <Typography variant="caption" color="text.secondary">Rules Applied</Typography>
                    <Typography variant="h6">{currentProxy.stats.rules_applied}</Typography>
                  </Box>
                </Box>
              </Box>

              {/* Tabs */}
              <Tabs value={tabValue} onChange={(_, v) => setTabValue(v)} sx={{ px: 2, borderBottom: 1, borderColor: 'divider' }}>
                <Tab label="Traffic Log" icon={<HttpIcon />} iconPosition="start" />
                <Tab label="Interception Rules" icon={<RuleIcon />} iconPosition="start" />
                <Tab label="Preset Rules" icon={<SecurityIcon />} iconPosition="start" />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      AI Analysis
                      {analysisResult && (
                        <Chip 
                          label={analysisResult.risk_level} 
                          size="small" 
                          sx={{ 
                            bgcolor: getRiskLevelColor(analysisResult.risk_level),
                            color: 'white',
                            height: 20,
                            fontSize: '0.7rem',
                          }} 
                        />
                      )}
                    </Box>
                  } 
                  icon={<AIIcon />} 
                  iconPosition="start" 
                />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      WebSocket
                      {wsConnections.length > 0 && (
                        <Chip 
                          label={wsConnections.filter(c => c.status === 'active').length} 
                          size="small" 
                          color="primary"
                          sx={{ height: 20, fontSize: '0.7rem' }} 
                        />
                      )}
                    </Box>
                  }
                  icon={<SwapIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label="Certificates"
                  icon={<LockIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      Templates
                      {templates.length > 0 && (
                        <Chip 
                          label={templates.length} 
                          size="small" 
                          sx={{ height: 20, fontSize: '0.7rem' }} 
                        />
                      )}
                    </Box>
                  }
                  icon={<RuleIcon />}
                  iconPosition="start"
                />
                <Tab 
                  label="HTTP/2 & gRPC"
                  icon={<SpeedIcon />}
                  iconPosition="start"
                />
              </Tabs>

              {/* Tab panels */}
              <Box sx={{ flex: 1, overflow: 'auto' }}>
                {/* Traffic Log Tab */}
                <TabPanel value={tabValue} index={0}>
                  <Box sx={{ mb: 2 }}>
                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center', mb: 1 }}>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={liveStreamEnabled}
                            onChange={(e) => setLiveStreamEnabled(e.target.checked)}
                            disabled={!selectedProxy || Boolean(activeSession)}
                          />
                        }
                        label={
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            Live Stream
                            {liveStreamEnabled && (
                              <Chip
                                size="small"
                                color={wsConnected ? 'success' : 'warning'}
                                icon={wsConnected ? <WifiIcon /> : <WifiOffIcon />}
                                label={wsConnected ? 'Connected' : 'Connecting'}
                              />
                            )}
                          </Box>
                        }
                      />
                      {wsError && (
                        <Tooltip title={wsError}>
                          <Chip size="small" color="error" label="Stream error" />
                        </Tooltip>
                      )}
                      <FormControlLabel
                        control={
                          <Switch
                            checked={autoRefresh}
                            onChange={(e) => setAutoRefresh(e.target.checked)}
                            disabled={liveStreamEnabled || Boolean(activeSession)}
                          />
                        }
                        label="Auto Refresh"
                      />
                      <Button
                        size="small"
                        startIcon={<RefreshIcon />}
                        onClick={loadTraffic}
                        disabled={Boolean(activeSession)}
                      >
                        Refresh
                      </Button>
                      <Button
                        size="small"
                        startIcon={<ClearIcon />}
                        onClick={handleClearTraffic}
                        disabled={Boolean(activeSession)}
                      >
                        Clear
                      </Button>
                      <Button
                        size="small"
                        startIcon={<DownloadIcon />}
                        onClick={(e) => setTrafficExportAnchorEl(e.currentTarget)}
                        disabled={traffic.length === 0 || trafficExporting}
                      >
                        Export
                      </Button>
                      <Button
                        size="small"
                        startIcon={<HistoryIcon />}
                        onClick={handleOpenSessions}
                        disabled={!selectedProxy}
                      >
                        Sessions
                      </Button>
                      <Menu
                        anchorEl={trafficExportAnchorEl}
                        open={Boolean(trafficExportAnchorEl)}
                        onClose={() => setTrafficExportAnchorEl(null)}
                      >
                        <MenuItem onClick={() => exportTraffic('json')}>
                          <ListItemIcon>
                            <MarkdownIcon fontSize="small" />
                          </ListItemIcon>
                          JSON
                        </MenuItem>
                        <MenuItem onClick={() => exportTraffic('pcap')}>
                          <ListItemIcon>
                            <NetworkIcon fontSize="small" />
                          </ListItemIcon>
                          PCAP
                        </MenuItem>
                      </Menu>
                    </Box>

                    {activeSession && (
                      <Alert
                        severity="info"
                        sx={{ mb: 1 }}
                        action={
                          <Button color="inherit" size="small" onClick={handleExitSession}>
                            Back to live
                          </Button>
                        }
                      >
                        Viewing session: {activeSession.name} - {activeSession.entries} entries
                      </Alert>
                    )}

                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                      <TextField
                        size="small"
                        placeholder="Search path, host, headers, body"
                        value={trafficSearch}
                        onChange={(e) => setTrafficSearch(e.target.value)}
                        sx={{ minWidth: 240 }}
                        InputProps={{
                          startAdornment: (
                            <InputAdornment position="start">
                              <SearchIcon fontSize="small" />
                            </InputAdornment>
                          ),
                        }}
                      />
                      <FormControl size="small" sx={{ minWidth: 140 }}>
                        <InputLabel>Method</InputLabel>
                        <Select
                          multiple
                          value={trafficMethodFilter}
                          onChange={(e) => {
                            const value = e.target.value as string[];
                            setTrafficMethodFilter(value);
                          }}
                          renderValue={(selected) => (selected as string[]).join(', ') || 'All'}
                          label="Method"
                        >
                          {uniqueMethods.length === 0 && (
                            <MenuItem disabled value="">
                              <ListItemText primary="No methods yet" />
                            </MenuItem>
                          )}
                          {uniqueMethods.map((method) => (
                            <MenuItem key={method} value={method}>
                              <Checkbox checked={trafficMethodFilter.indexOf(method) > -1} />
                              <ListItemText primary={method} />
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 130 }}>
                        <InputLabel>Status</InputLabel>
                        <Select
                          value={trafficStatusFilter}
                          label="Status"
                          onChange={(e) => setTrafficStatusFilter(e.target.value as string)}
                        >
                          <MenuItem value="all">All</MenuItem>
                          <MenuItem value="2xx">2xx Success</MenuItem>
                          <MenuItem value="3xx">3xx Redirect</MenuItem>
                          <MenuItem value="4xx">4xx Client</MenuItem>
                          <MenuItem value="5xx">5xx Server</MenuItem>
                          <MenuItem value="pending">Pending</MenuItem>
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 160 }}>
                        <InputLabel>Host</InputLabel>
                        <Select
                          value={trafficHostFilter}
                          label="Host"
                          onChange={(e) => setTrafficHostFilter(e.target.value as string)}
                        >
                          <MenuItem value="all">All hosts</MenuItem>
                          {uniqueHosts.map((host) => (
                            <MenuItem key={host} value={host}>{host}</MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      <FormControl size="small" sx={{ minWidth: 120 }}>
                        <InputLabel>Sort</InputLabel>
                        <Select
                          value={trafficSort}
                          label="Sort"
                          onChange={(e) => setTrafficSort(e.target.value as 'newest' | 'oldest')}
                        >
                          <MenuItem value="newest">Newest</MenuItem>
                          <MenuItem value="oldest">Oldest</MenuItem>
                        </Select>
                      </FormControl>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={trafficModifiedOnly}
                            onChange={(e) => setTrafficModifiedOnly(e.target.checked)}
                          />
                        }
                        label="Modified only"
                      />
                      <FormControlLabel
                        control={
                          <Switch
                            checked={trafficWithResponseOnly}
                            onChange={(e) => setTrafficWithResponseOnly(e.target.checked)}
                          />
                        }
                        label="With response"
                      />
                    </Box>

                    <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Chip label={`${trafficSummary.total} total`} size="small" />
                      {hasActiveTrafficFilters && (
                        <Chip label={`${filteredTraffic.length} shown`} size="small" color="info" />
                      )}
                      <Chip
                        label={`${trafficSummary.errors} errors`}
                        size="small"
                        color={trafficSummary.errors > 0 ? 'warning' : 'default'}
                      />
                      <Chip
                        label={`${trafficSummary.modified} modified`}
                        size="small"
                        color={trafficSummary.modified > 0 ? 'warning' : 'default'}
                      />
                      <Chip label={`${trafficSummary.hosts} hosts`} size="small" />
                      {trafficSummary.avgDuration > 0 && (
                        <Chip label={`Avg ${trafficSummary.avgDuration}ms`} size="small" />
                      )}
                    </Box>
                  </Box>

                  <TableContainer>
                    <Table size="small" stickyHeader>
                      <TableHead>
                        <TableRow>
                          <TableCell>Time</TableCell>
                          <TableCell>Method</TableCell>
                          <TableCell>Path</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Duration</TableCell>
                          <TableCell>Modified</TableCell>
                          <TableCell>Actions</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {traffic.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={7} align="center">
                              <Typography color="text.secondary">No traffic captured yet</Typography>
                            </TableCell>
                          </TableRow>
                        ) : filteredTraffic.length === 0 ? (
                          <TableRow>
                            <TableCell colSpan={7} align="center">
                              <Typography color="text.secondary">No traffic matches the current filters</Typography>
                            </TableCell>
                          </TableRow>
                        ) : (
                          filteredTraffic.map((entry) => (
                            <TableRow
                              key={entry.id}
                              hover
                              sx={{
                                bgcolor: entry.modified ? 'action.selected' : 'inherit',
                              }}
                            >
                              <TableCell>
                                <Typography variant="caption">
                                  {new Date(entry.timestamp).toLocaleTimeString()}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                <Chip
                                  label={entry.request.method}
                                  size="small"
                                  color={
                                    entry.request.method === 'GET' ? 'info' :
                                    entry.request.method === 'POST' ? 'success' :
                                    entry.request.method === 'PUT' ? 'warning' :
                                    entry.request.method === 'DELETE' ? 'error' : 'default'
                                  }
                                />
                              </TableCell>
                              <TableCell>
                                <Typography
                                  variant="body2"
                                  sx={{
                                    maxWidth: 300,
                                    overflow: 'hidden',
                                    textOverflow: 'ellipsis',
                                    whiteSpace: 'nowrap',
                                  }}
                                >
                                  {entry.request.path}
                                </Typography>
                                {entry.request.host && (
                                  <Typography variant="caption" color="text.secondary">
                                    {entry.request.host}
                                  </Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                {entry.response ? (
                                  <Chip
                                    label={entry.response.status_code}
                                    size="small"
                                    color={
                                      entry.response.status_code < 300 ? 'success' :
                                      entry.response.status_code < 400 ? 'info' :
                                      entry.response.status_code < 500 ? 'warning' : 'error'
                                    }
                                  />
                                ) : (
                                  <Typography variant="caption" color="text.secondary">Pending</Typography>
                                )}
                              </TableCell>
                              <TableCell>
                                <Typography variant="body2">
                                  {entry.duration_ms ? `${Math.round(entry.duration_ms)}ms` : '-'}
                                </Typography>
                              </TableCell>
                              <TableCell>
                                {entry.modified && (
                                  <Chip label="Modified" size="small" color="warning" />
                                )}
                              </TableCell>
                              <TableCell>
                                <Tooltip title="View details">
                                  <IconButton
                                    size="small"
                                    onClick={() => {
                                      setSelectedTraffic(entry);
                                      setTrafficDetailOpen(true);
                                    }}
                                  >
                                    <ViewIcon />
                                  </IconButton>
                                </Tooltip>
                                <Tooltip title="Actions">
                                  <IconButton
                                    size="small"
                                    onClick={(event) => openTrafficMenu(event, entry)}
                                  >
                                    <MoreIcon />
                                  </IconButton>
                                </Tooltip>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                  <Menu
                    anchorEl={trafficMenuAnchor}
                    open={Boolean(trafficMenuAnchor)}
                    onClose={closeTrafficMenu}
                  >
                    <MenuItem
                      onClick={() => {
                        if (trafficMenuEntry) {
                          setSelectedTraffic(trafficMenuEntry);
                          setTrafficDetailOpen(true);
                        }
                        closeTrafficMenu();
                      }}
                    >
                      <ListItemIcon>
                        <ViewIcon fontSize="small" />
                      </ListItemIcon>
                      View details
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCopyAsCurl(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <CopyIcon fontSize="small" />
                      </ListItemIcon>
                      Copy as curl
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleOpenReplay(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <ReplayIcon fontSize="small" />
                      </ListItemIcon>
                      Replay request
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleSendToApiTester(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <SwapIcon fontSize="small" />
                      </ListItemIcon>
                      Send to API Tester
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleSendToFuzzer(trafficMenuEntry)}
                    >
                      <ListItemIcon>
                        <ScienceIcon fontSize="small" />
                      </ListItemIcon>
                      Send to Fuzzer
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCreateRuleFromEntry(trafficMenuEntry, 'modify')}
                    >
                      <ListItemIcon>
                        <RuleIcon fontSize="small" />
                      </ListItemIcon>
                      Create rule from request
                    </MenuItem>
                    <MenuItem
                      onClick={() => trafficMenuEntry && handleCreateRuleFromEntry(trafficMenuEntry, 'drop')}
                    >
                      <ListItemIcon>
                        <CancelIcon fontSize="small" />
                      </ListItemIcon>
                      Block host
                    </MenuItem>
                  </Menu>
                </TabPanel>

                {/* Interception Rules Tab */}
                <TabPanel value={tabValue} index={1}>
                  <Box sx={{ mb: 2 }}>
                    <Button
                      variant="contained"
                      startIcon={<AddIcon />}
                      onClick={() => setNewRuleOpen(true)}
                    >
                      Add Rule
                    </Button>
                  </Box>

                  {ruleGroups.length > 0 && (
                    <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
                      <Typography variant="caption" color="text.secondary">
                        Rule groups
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', mt: 1 }}>
                        {ruleGroups.map(group => (
                          <FormControlLabel
                            key={group.name}
                            control={
                              <Switch
                                size="small"
                                checked={group.allEnabled}
                                onChange={(e) => handleToggleRuleGroup(group.name, e.target.checked)}
                              />
                            }
                            label={`${group.name} (${group.enabledCount}/${group.total})`}
                          />
                        ))}
                      </Box>
                    </Paper>
                  )}

                  {rules.length === 0 ? (
                    <Alert severity="info">
                      No interception rules configured. Add rules to automatically modify traffic.
                    </Alert>
                  ) : (
                    <List>
                      {rules.map((rule) => (
                        <Card key={rule.id} sx={{ mb: 1 }}>
                          <CardContent sx={{ pb: 1 }}>
                            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                <Switch
                                  checked={rule.enabled}
                                  size="small"
                                  onChange={(e) => handleToggleRule(rule.id, e.target.checked)}
                                />
                                <Typography variant="subtitle1">{rule.name}</Typography>
                                <Chip
                                  label={rule.match_direction}
                                  size="small"
                                  color={
                                    rule.match_direction === 'request' ? 'primary' :
                                    rule.match_direction === 'response' ? 'secondary' : 'default'
                                  }
                                />
                                <Chip
                                  label={rule.action}
                                  size="small"
                                  color={
                                    rule.action === 'modify' ? 'info' :
                                    rule.action === 'drop' ? 'error' : 'warning'
                                  }
                                />
                              </Box>
                              <IconButton
                                size="small"
                                color="error"
                                onClick={() => handleDeleteRule(rule.id)}
                              >
                                <DeleteIcon />
                              </IconButton>
                            </Box>
                            <Box sx={{ mt: 1, display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              {rule.group && <Chip label={`Group: ${rule.group}`} size="small" variant="outlined" />}
                              {typeof rule.priority === 'number' && <Chip label={`Priority: ${rule.priority}`} size="small" variant="outlined" />}
                              {rule.match_query && Object.keys(rule.match_query).length > 0 && (
                                <Chip label={`Query: ${Object.keys(rule.match_query).length}`} size="small" variant="outlined" />
                              )}
                              {rule.match_host && <Chip label={`Host: ${rule.match_host}`} size="small" variant="outlined" />}
                              {rule.match_path && <Chip label={`Path: ${rule.match_path}`} size="small" variant="outlined" />}
                              {rule.match_method && <Chip label={`Method: ${rule.match_method}`} size="small" variant="outlined" />}
                              {rule.match_content_type && <Chip label={`Type: ${rule.match_content_type}`} size="small" variant="outlined" />}
                              {rule.modify_path && <Chip label={`Rewrite: ${rule.modify_path}`} size="small" variant="outlined" />}
                              {typeof rule.modify_status_code === 'number' && <Chip label={`Status: ${rule.modify_status_code}`} size="small" variant="outlined" />}
                              {rule.body_find_replace_regex && <Chip label="Body regex" size="small" variant="outlined" />}
                              {rule.delay_ms && rule.delay_ms > 0 && <Chip label={`Delay: ${rule.delay_ms}ms`} size="small" variant="outlined" />}
                              {typeof rule.hit_count === 'number' && <Chip label={`Hits: ${rule.hit_count}`} size="small" variant="outlined" />}
                            </Box>
                          </CardContent>
                        </Card>
                      ))}
                    </List>
                  )}
                </TabPanel>

                {/* Preset Rules Tab */}
                <TabPanel value={tabValue} index={2}>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    Preset rules provide common MITM scenarios for security testing. Click to apply them to the current proxy.
                  </Alert>

                  <Grid container spacing={2}>
                    {presets.map((preset) => (
                      <Grid item xs={12} sm={6} md={4} key={preset.id}>
                        <Card>
                          <CardContent>
                            <Typography variant="subtitle1" gutterBottom>
                              {preset.name}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {preset.id.replace(/_/g, ' ')}
                            </Typography>
                          </CardContent>
                          <CardActions>
                            <Button
                              size="small"
                              onClick={() => handleApplyPreset(preset.id)}
                            >
                              Apply
                            </Button>
                          </CardActions>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </TabPanel>

                {/* AI Analysis Tab */}
                <TabPanel value={tabValue} index={3}>
                  {!analysisResult ? (
                    <Box sx={{ textAlign: 'center', py: 4 }}>
                      <AIIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
                      <Typography variant="h6" color="text.secondary" gutterBottom>
                        No Analysis Available
                      </Typography>
                      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Click the "Analyze" button to run AI-powered security analysis on your captured traffic.
                      </Typography>
                      <Button
                        variant="contained"
                        color="secondary"
                        startIcon={analyzingTraffic ? <CircularProgress size={20} color="inherit" /> : <AIIcon />}
                        onClick={handleAnalyzeTraffic}
                        disabled={analyzingTraffic || traffic.length === 0}
                      >
                        {analyzingTraffic ? 'Analyzing...' : 'Analyze Traffic'}
                      </Button>
                      {traffic.length === 0 && (
                        <Typography variant="caption" display="block" color="error" sx={{ mt: 1 }}>
                          Capture some traffic first before analyzing
                        </Typography>
                      )}
                    </Box>
                  ) : (
                    <Box>
                      {/* Risk Score Overview */}
                      <Paper sx={{ p: 3, mb: 3, bgcolor: 'background.default' }}>
                        <Grid container spacing={3} alignItems="center">
                          <Grid item>
                            <Box 
                              sx={{ 
                                width: 100, 
                                height: 100, 
                                borderRadius: '50%', 
                                display: 'flex', 
                                alignItems: 'center', 
                                justifyContent: 'center',
                                bgcolor: getRiskLevelColor(analysisResult.risk_level),
                                color: 'white',
                              }}
                            >
                              <Box sx={{ textAlign: 'center' }}>
                                <Typography variant="h4" fontWeight="bold">
                                  {analysisResult.risk_score}
                                </Typography>
                                <Typography variant="caption">/100</Typography>
                              </Box>
                            </Box>
                          </Grid>
                          <Grid item xs>
                            <Typography variant="h5" gutterBottom>
                              {analysisResult.risk_level.toUpperCase()} RISK
                            </Typography>
                            <Typography variant="body1" color="text.secondary">
                              {analysisResult.summary}
                            </Typography>
                            <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
                              <Chip 
                                icon={<HttpIcon />} 
                                label={`${analysisResult.traffic_analyzed} requests analyzed`} 
                                variant="outlined" 
                              />
                              <Chip 
                                icon={<RuleIcon />} 
                                label={`${analysisResult.rules_active} rules active`} 
                                variant="outlined" 
                              />
                              <Chip 
                                icon={<WarningIcon />} 
                                label={`${analysisResult.findings.length} findings`} 
                                variant="outlined" 
                                color={analysisResult.findings.length > 0 ? 'warning' : 'default'}
                              />
                            </Box>
                          </Grid>
                          <Grid item>
                            <Button
                              variant="outlined"
                              startIcon={<RefreshIcon />}
                              onClick={handleAnalyzeTraffic}
                              disabled={analyzingTraffic}
                            >
                              Re-analyze
                            </Button>
                          </Grid>
                        </Grid>
                      </Paper>

                      {/* Findings */}
                      {analysisResult.findings.length > 0 && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <ShieldIcon /> Security Findings
                          </Typography>
                          {analysisResult.findings.map((finding, index) => (
                            <Accordion key={index} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                                  <Chip 
                                    label={finding.severity} 
                                    size="small" 
                                    color={getSeverityColor(finding.severity) as any}
                                  />
                                  <Typography fontWeight="medium">{finding.title}</Typography>
                                  <Chip label={finding.category} size="small" variant="outlined" sx={{ ml: 'auto', mr: 2 }} />
                                </Box>
                              </AccordionSummary>
                              <AccordionDetails>
                                <Typography variant="body2" paragraph>
                                  {finding.description}
                                </Typography>
                                {finding.evidence && (
                                  <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1, mb: 2 }}>
                                    <Typography variant="caption" color="text.secondary">Evidence</Typography>
                                    <pre style={{ margin: 0, fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                                      {finding.evidence}
                                    </pre>
                                  </Box>
                                )}
                                <Alert severity="info" icon={<IdeaIcon />}>
                                  <AlertTitle>Recommendation</AlertTitle>
                                  {finding.recommendation}
                                </Alert>
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* AI Analysis (if available) */}
                      {analysisResult.ai_analysis && (
                        <Box sx={{ mb: 3 }}>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <AIIcon /> AI Analysis
                          </Typography>
                          <Paper sx={{ p: 2, bgcolor: 'background.default' }}>
                            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
                              {analysisResult.ai_analysis}
                            </Typography>
                          </Paper>
                        </Box>
                      )}

                      {/* Recommendations */}
                      {analysisResult.recommendations.length > 0 && (
                        <Box>
                          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <TipIcon /> Recommendations
                          </Typography>
                          <List>
                            {analysisResult.recommendations.map((rec, index) => (
                              <ListItem key={index}>
                                <ListItemIcon>
                                  <SuccessIcon color="primary" />
                                </ListItemIcon>
                                <ListItemText primary={rec} />
                              </ListItem>
                            ))}
                          </List>
                        </Box>
                      )}
                    </Box>
                  )}
                </TabPanel>

                {/* WebSocket Tab */}
                <TabPanel value={tabValue} index={4}>
                  <Box sx={{ p: 2 }}>
                    {/* WebSocket Stats */}
                    {wsStats && (
                      <Box sx={{ display: 'flex', gap: 3, mb: 3, flexWrap: 'wrap' }}>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Active Connections</Typography>
                          <Typography variant="h5" color="primary">{wsStats.active_connections}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Total Connections</Typography>
                          <Typography variant="h5">{wsStats.total_connections}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Client → Server</Typography>
                          <Typography variant="h5">{wsStats.frames_client_to_server}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Server → Client</Typography>
                          <Typography variant="h5">{wsStats.frames_server_to_client}</Typography>
                        </Paper>
                        <Paper sx={{ p: 2, flex: '1 1 150px', textAlign: 'center' }}>
                          <Typography variant="caption" color="text.secondary">Rules Applied</Typography>
                          <Typography variant="h5">{wsStats.rules_applied}</Typography>
                        </Paper>
                      </Box>
                    )}

                    {/* Toolbar */}
                    <Box sx={{ display: 'flex', gap: 1, mb: 2, alignItems: 'center' }}>
                      <Button 
                        size="small" 
                        startIcon={<RefreshIcon />} 
                        onClick={() => { loadWebSocketConnections(); loadWebSocketStats(); }}
                        disabled={wsLoadingConnections}
                      >
                        Refresh
                      </Button>
                      <Button 
                        size="small" 
                        variant="outlined" 
                        startIcon={<AddIcon />}
                        onClick={() => setWsNewRuleOpen(true)}
                      >
                        Add WS Rule
                      </Button>
                    </Box>

                    <Grid container spacing={2}>
                      {/* Connections List */}
                      <Grid item xs={12} md={4}>
                        <Paper sx={{ p: 2, height: 400, overflow: 'auto' }}>
                          <Typography variant="subtitle2" gutterBottom>WebSocket Connections</Typography>
                          {wsLoadingConnections ? (
                            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                              <CircularProgress size={24} />
                            </Box>
                          ) : wsConnections.length === 0 ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              No WebSocket connections captured
                            </Typography>
                          ) : (
                            <List dense>
                              {wsConnections.map((conn) => (
                                <ListItem 
                                  key={conn.id}
                                  button
                                  selected={selectedWsConnection === conn.id}
                                  onClick={() => {
                                    setSelectedWsConnection(conn.id);
                                    loadWebSocketFrames(conn.id);
                                  }}
                                  sx={{ 
                                    borderRadius: 1,
                                    mb: 0.5,
                                    bgcolor: selectedWsConnection === conn.id ? 'action.selected' : 'transparent',
                                  }}
                                >
                                  <ListItemIcon>
                                    <Chip 
                                      size="small" 
                                      label={conn.status} 
                                      color={conn.status === 'active' ? 'success' : 'default'}
                                      sx={{ minWidth: 70 }}
                                    />
                                  </ListItemIcon>
                                  <ListItemText 
                                    primary={`${conn.target_host}:${conn.target_port}`}
                                    secondary={`${conn.total_frames} frames • ${new Date(conn.created_at).toLocaleTimeString()}`}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          )}
                        </Paper>
                      </Grid>

                      {/* Frames List */}
                      <Grid item xs={12} md={8}>
                        <Paper sx={{ p: 2, height: 400, overflow: 'auto' }}>
                          <Typography variant="subtitle2" gutterBottom>
                            WebSocket Frames {selectedWsConnection && `(${wsFrames.length} frames)`}
                          </Typography>
                          {!selectedWsConnection ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              Select a connection to view frames
                            </Typography>
                          ) : wsLoadingFrames ? (
                            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                              <CircularProgress size={24} />
                            </Box>
                          ) : wsFrames.length === 0 ? (
                            <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
                              No frames captured
                            </Typography>
                          ) : (
                            <TableContainer sx={{ maxHeight: 320 }}>
                              <Table size="small" stickyHeader>
                                <TableHead>
                                  <TableRow>
                                    <TableCell>Time</TableCell>
                                    <TableCell>Direction</TableCell>
                                    <TableCell>Type</TableCell>
                                    <TableCell>Size</TableCell>
                                    <TableCell>Data</TableCell>
                                  </TableRow>
                                </TableHead>
                                <TableBody>
                                  {wsFrames.map((frame) => (
                                    <TableRow 
                                      key={frame.id} 
                                      hover
                                      onClick={() => setWsSelectedFrame(frame)}
                                      sx={{ 
                                        cursor: 'pointer',
                                        bgcolor: frame.modified ? alpha(theme.palette.warning.main, 0.1) : 'inherit',
                                      }}
                                    >
                                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                        {new Date(frame.timestamp).toLocaleTimeString()}
                                      </TableCell>
                                      <TableCell>
                                        <Chip 
                                          size="small" 
                                          label={frame.direction === 'client_to_server' ? '→' : '←'}
                                          color={frame.direction === 'client_to_server' ? 'primary' : 'secondary'}
                                          sx={{ minWidth: 40 }}
                                        />
                                      </TableCell>
                                      <TableCell>
                                        <Chip 
                                          size="small" 
                                          label={frame.opcode_name}
                                          variant="outlined"
                                        />
                                      </TableCell>
                                      <TableCell>{frame.payload_length}B</TableCell>
                                      <TableCell sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                        {frame.payload_text || frame.payload_hex || '-'}
                                      </TableCell>
                                    </TableRow>
                                  ))}
                                </TableBody>
                              </Table>
                            </TableContainer>
                          )}
                        </Paper>
                      </Grid>
                    </Grid>

                    {/* WebSocket Rules */}
                    <Box sx={{ mt: 3 }}>
                      <Typography variant="subtitle2" gutterBottom>WebSocket Rules</Typography>
                      {wsRules.length === 0 ? (
                        <Typography variant="body2" color="text.secondary">
                          No WebSocket rules configured. Click "Add WS Rule" to create one.
                        </Typography>
                      ) : (
                        <TableContainer component={Paper}>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Enabled</TableCell>
                                <TableCell>Name</TableCell>
                                <TableCell>Direction</TableCell>
                                <TableCell>Action</TableCell>
                                <TableCell>Hits</TableCell>
                                <TableCell>Actions</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {wsRules.map((rule) => (
                                <TableRow key={rule.id}>
                                  <TableCell>
                                    <Chip 
                                      size="small" 
                                      label={rule.enabled ? 'On' : 'Off'}
                                      color={rule.enabled ? 'success' : 'default'}
                                    />
                                  </TableCell>
                                  <TableCell>{rule.name}</TableCell>
                                  <TableCell>{rule.match_direction}</TableCell>
                                  <TableCell>{rule.action}</TableCell>
                                  <TableCell>{rule.hit_count}</TableCell>
                                  <TableCell>
                                    <IconButton 
                                      size="small" 
                                      color="error"
                                      onClick={() => handleRemoveWebSocketRule(rule.id)}
                                    >
                                      <DeleteIcon fontSize="small" />
                                    </IconButton>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      )}
                    </Box>
                  </Box>
                </TabPanel>

                {/* Certificates Tab */}
                <TabPanel value={tabValue} index={5}>
                  <Box sx={{ p: 2 }}>
                    {/* CA Certificate Section */}
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <LockIcon /> CA Certificate
                    </Typography>
                    
                    {certLoading ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                        <CircularProgress />
                      </Box>
                    ) : caCertificate ? (
                      <Paper sx={{ p: 2, mb: 3 }}>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="body2" color="text.secondary">Common Name</Typography>
                            <Typography variant="body1" gutterBottom>{caCertificate.common_name}</Typography>
                            
                            <Typography variant="body2" color="text.secondary">Organization</Typography>
                            <Typography variant="body1" gutterBottom>{caCertificate.organization}</Typography>
                            
                            <Typography variant="body2" color="text.secondary">Valid Until</Typography>
                            <Typography variant="body1" gutterBottom>
                              {new Date(caCertificate.valid_until).toLocaleDateString()}
                            </Typography>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="body2" color="text.secondary">Fingerprint (SHA-256)</Typography>
                            <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', mb: 2 }}>
                              {caCertificate.fingerprint_sha256}
                            </Typography>
                            
                            <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                              <Button 
                                variant="contained" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('pem')}
                              >
                                Download PEM
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('crt')}
                              >
                                Download CRT
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<DownloadIcon />}
                                onClick={() => handleDownloadCACertificate('der')}
                              >
                                Download DER
                              </Button>
                              <Button 
                                variant="outlined" 
                                size="small"
                                startIcon={<HelpIcon />}
                                onClick={() => {
                                  loadCertificateInstallInstructions();
                                  setShowCertInstallDialog(true);
                                }}
                              >
                                Installation Guide
                              </Button>
                            </Box>
                          </Grid>
                        </Grid>
                        
                        <Divider sx={{ my: 2 }} />
                        
                        <Button 
                          variant="outlined" 
                          color="warning"
                          startIcon={<RefreshIcon />}
                          onClick={() => setShowCertGenDialog(true)}
                        >
                          Regenerate CA Certificate
                        </Button>
                      </Paper>
                    ) : (
                      <Paper sx={{ p: 3, mb: 3, textAlign: 'center' }}>
                        <LockOpenIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 2 }} />
                        <Typography variant="body1" gutterBottom>
                          No CA certificate generated yet
                        </Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          Generate a CA certificate to enable HTTPS interception
                        </Typography>
                        <Button 
                          variant="contained"
                          startIcon={<AddIcon />}
                          onClick={() => setShowCertGenDialog(true)}
                        >
                          Generate CA Certificate
                        </Button>
                      </Paper>
                    )}

                    {/* Host Certificates Section */}
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 3 }}>
                      <SecurityIcon /> Host Certificates
                    </Typography>
                    
                    {hostCertificates.length === 0 ? (
                      <Typography variant="body2" color="text.secondary">
                        No host certificates generated yet. They are created automatically when intercepting HTTPS traffic.
                      </Typography>
                    ) : (
                      <TableContainer component={Paper}>
                        <Table size="small">
                          <TableHead>
                            <TableRow>
                              <TableCell>Hostname</TableCell>
                              <TableCell>Created</TableCell>
                              <TableCell>Valid Until</TableCell>
                              <TableCell>Fingerprint</TableCell>
                              <TableCell>Actions</TableCell>
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {hostCertificates.map((cert) => (
                              <TableRow key={cert.hostname}>
                                <TableCell sx={{ fontFamily: 'monospace' }}>{cert.hostname}</TableCell>
                                <TableCell>{new Date(cert.created_at).toLocaleDateString()}</TableCell>
                                <TableCell>{new Date(cert.valid_until).toLocaleDateString()}</TableCell>
                                <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                  {cert.fingerprint_sha256.substring(0, 32)}...
                                </TableCell>
                                <TableCell>
                                  <IconButton 
                                    size="small" 
                                    color="error"
                                    onClick={() => handleDeleteHostCertificate(cert.hostname)}
                                  >
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </TableContainer>
                    )}
                  </Box>
                </TabPanel>

                {/* Templates Tab */}
                <TabPanel value={tabValue} index={6}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {/* Templates Header */}
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="h6">Match & Replace Templates</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Pre-built rule templates for common MITM modifications
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <FormControl size="small" sx={{ minWidth: 150 }}>
                          <InputLabel>Category</InputLabel>
                          <Select
                            value={selectedTemplateCategory}
                            label="Category"
                            onChange={(e) => {
                              setSelectedTemplateCategory(e.target.value);
                              loadTemplates(e.target.value || undefined);
                            }}
                          >
                            <MenuItem value="">All Categories</MenuItem>
                            {templateCategories.map((cat) => (
                              <MenuItem key={cat} value={cat}>{cat}</MenuItem>
                            ))}
                          </Select>
                        </FormControl>
                        <Button
                          variant="contained"
                          startIcon={<AddIcon />}
                          onClick={() => setShowNewTemplateDialog(true)}
                        >
                          Create Template
                        </Button>
                      </Box>
                    </Box>

                    {/* Templates List */}
                    {templatesLoading ? (
                      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
                        <CircularProgress />
                      </Box>
                    ) : templates.length === 0 ? (
                      <Alert severity="info">
                        No templates found. Select a category or create a custom template.
                      </Alert>
                    ) : (
                      <Grid container spacing={2}>
                        {templates.map((template) => (
                          <Grid item xs={12} md={6} lg={4} key={template.id}>
                            <Card variant="outlined">
                              <CardContent>
                                <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', mb: 1 }}>
                                  <Typography variant="subtitle1" fontWeight="medium">
                                    {template.name}
                                  </Typography>
                                  {template.is_builtin && (
                                    <Chip label="Built-in" size="small" color="default" />
                                  )}
                                </Box>
                                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                  {template.description}
                                </Typography>
                                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                                  <Chip label={template.category} size="small" color="primary" variant="outlined" />
                                  <Chip label={template.match_type} size="small" />
                                  <Chip label={template.direction} size="small" />
                                </Box>
                                {template.tags && template.tags.length > 0 && (
                                  <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                                    {template.tags.map((tag: string) => (
                                      <Chip key={tag} label={tag} size="small" variant="outlined" />
                                    ))}
                                  </Box>
                                )}
                                <Divider sx={{ my: 1 }} />
                                <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontSize: '0.75rem', fontFamily: 'monospace' }}>
                                  <Box><strong>Match:</strong> {template.match_pattern}</Box>
                                  <Box><strong>Replace:</strong> {template.replace_pattern}</Box>
                                </Box>
                              </CardContent>
                              <CardActions>
                                <Button
                                  size="small"
                                  startIcon={<PlayIcon />}
                                  onClick={() => handleApplyTemplate(template.id)}
                                  disabled={!selectedProxy}
                                >
                                  Apply
                                </Button>
                                <Button
                                  size="small"
                                  startIcon={<ScienceIcon />}
                                  onClick={() => {
                                    setSelectedTemplate(template);
                                    handleTestTemplate(template.id);
                                  }}
                                  disabled={!selectedTraffic || testingTemplate}
                                >
                                  Test
                                </Button>
                                {!template.is_builtin && (
                                  <IconButton
                                    size="small"
                                    color="error"
                                    onClick={() => handleDeleteTemplate(template.id)}
                                  >
                                    <DeleteIcon fontSize="small" />
                                  </IconButton>
                                )}
                              </CardActions>
                            </Card>
                          </Grid>
                        ))}
                      </Grid>
                    )}

                    {/* Template Test Result */}
                    {templateTestResult && (
                      <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
                        <Typography variant="h6" gutterBottom>Test Result</Typography>
                        <Alert severity={templateTestResult.matched ? 'success' : 'info'} sx={{ mb: 2 }}>
                          {templateTestResult.matched ? 'Template matched!' : 'Template did not match the traffic.'}
                        </Alert>
                        {templateTestResult.matched && templateTestResult.preview && (
                          <Box>
                            <Typography variant="subtitle2">Preview of Changes:</Typography>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 1 }}>
                              <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                                {JSON.stringify(templateTestResult.preview, null, 2)}
                              </pre>
                            </Box>
                          </Box>
                        )}
                        <Button
                          size="small"
                          onClick={() => setTemplateTestResult(null)}
                          sx={{ mt: 1 }}
                        >
                          Clear Result
                        </Button>
                      </Paper>
                    )}
                  </Box>
                </TabPanel>

                {/* HTTP/2 & gRPC Tab */}
                <TabPanel value={tabValue} index={7}>
                  <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                    {/* HTTP/2 & gRPC Header */}
                    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <Box>
                        <Typography variant="h6">HTTP/2 & gRPC Inspector</Typography>
                        <Typography variant="body2" color="text.secondary">
                          Inspect HTTP/2 frames, streams, and gRPC messages
                        </Typography>
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        <Button
                          variant="outlined"
                          startIcon={http2Loading ? <CircularProgress size={16} /> : <RefreshIcon />}
                          onClick={() => {
                            if (selectedProxy) {
                              loadHTTP2Frames(selectedProxy);
                              loadHTTP2Streams(selectedProxy);
                              loadGRPCMessages(selectedProxy);
                            }
                          }}
                          disabled={!selectedProxy || http2Loading}
                        >
                          Refresh
                        </Button>
                      </Box>
                    </Box>

                    {/* HTTP/2 Streams */}
                    <Accordion defaultExpanded>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          HTTP/2 Streams ({http2Streams.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {http2Streams.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No HTTP/2 streams captured. HTTP/2 traffic will appear here when detected.
                          </Typography>
                        ) : (
                          <TableContainer>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell>Stream ID</TableCell>
                                  <TableCell>State</TableCell>
                                  <TableCell>Method</TableCell>
                                  <TableCell>Path</TableCell>
                                  <TableCell>Frames</TableCell>
                                  <TableCell>Actions</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {http2Streams.map((stream: any) => (
                                  <TableRow 
                                    key={stream.stream_id}
                                    selected={selectedHttp2Stream === stream.stream_id}
                                    onClick={() => setSelectedHttp2Stream(stream.stream_id)}
                                    sx={{ cursor: 'pointer' }}
                                  >
                                    <TableCell>{stream.stream_id}</TableCell>
                                    <TableCell>
                                      <Chip 
                                        label={stream.state} 
                                        size="small" 
                                        color={stream.state === 'open' ? 'success' : 'default'} 
                                      />
                                    </TableCell>
                                    <TableCell>{stream.method}</TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                      {stream.path}
                                    </TableCell>
                                    <TableCell>{stream.frame_count}</TableCell>
                                    <TableCell>
                                      <IconButton
                                        size="small"
                                        onClick={() => {
                                          setSelectedHttp2Stream(stream.stream_id);
                                          if (selectedProxy) {
                                            loadHTTP2Frames(selectedProxy, stream.stream_id);
                                          }
                                        }}
                                      >
                                        <ViewIcon fontSize="small" />
                                      </IconButton>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* HTTP/2 Frames */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          HTTP/2 Frames ({http2Frames.length})
                          {selectedHttp2Stream !== null && (
                            <Chip label={`Stream ${selectedHttp2Stream}`} size="small" sx={{ ml: 1 }} />
                          )}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        {http2Frames.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No HTTP/2 frames captured. Select a stream to view its frames.
                          </Typography>
                        ) : (
                          <TableContainer sx={{ maxHeight: 300 }}>
                            <Table size="small" stickyHeader>
                              <TableHead>
                                <TableRow>
                                  <TableCell>Type</TableCell>
                                  <TableCell>Stream</TableCell>
                                  <TableCell>Length</TableCell>
                                  <TableCell>Flags</TableCell>
                                  <TableCell>Timestamp</TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                {http2Frames.map((frame: any, idx: number) => (
                                  <TableRow key={idx}>
                                    <TableCell>
                                      <Chip 
                                        label={frame.frame_type} 
                                        size="small" 
                                        color={
                                          frame.frame_type === 'DATA' ? 'primary' :
                                          frame.frame_type === 'HEADERS' ? 'secondary' :
                                          frame.frame_type === 'RST_STREAM' ? 'error' : 'default'
                                        }
                                      />
                                    </TableCell>
                                    <TableCell>{frame.stream_id}</TableCell>
                                    <TableCell>{frame.length}</TableCell>
                                    <TableCell sx={{ fontFamily: 'monospace' }}>{frame.flags}</TableCell>
                                    <TableCell>{new Date(frame.timestamp).toLocaleTimeString()}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </TableContainer>
                        )}
                      </AccordionDetails>
                    </Accordion>

                    {/* gRPC Messages */}
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          gRPC Messages ({grpcMessages.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box sx={{ mb: 2 }}>
                          <TextField
                            size="small"
                            label="Filter by Service"
                            value={grpcServiceFilter}
                            onChange={(e) => setGrpcServiceFilter(e.target.value)}
                            placeholder="e.g., myapp.UserService"
                            InputProps={{
                              endAdornment: grpcServiceFilter && (
                                <IconButton size="small" onClick={() => setGrpcServiceFilter('')}>
                                  <ClearIcon fontSize="small" />
                                </IconButton>
                              ),
                            }}
                          />
                        </Box>
                        {grpcMessages.length === 0 ? (
                          <Typography variant="body2" color="text.secondary">
                            No gRPC messages captured. gRPC traffic will appear here when detected over HTTP/2.
                          </Typography>
                        ) : (
                          <List dense>
                            {grpcMessages
                              .filter((msg: any) => 
                                !grpcServiceFilter || 
                                msg.service?.toLowerCase().includes(grpcServiceFilter.toLowerCase())
                              )
                              .map((msg: any, idx: number) => (
                                <ListItem key={idx} divider>
                                  <ListItemText
                                    primary={
                                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <Chip 
                                          label={msg.is_request ? 'Request' : 'Response'} 
                                          size="small" 
                                          color={msg.is_request ? 'primary' : 'secondary'}
                                        />
                                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                                          {msg.service}/{msg.method}
                                        </Typography>
                                      </Box>
                                    }
                                    secondary={
                                      <Box sx={{ mt: 1 }}>
                                        <Typography variant="caption" color="text.secondary">
                                          Stream: {msg.stream_id} | Size: {msg.message_length} bytes
                                        </Typography>
                                        {msg.decoded_message && (
                                          <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 1 }}>
                                            <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', maxHeight: 100 }}>
                                              {JSON.stringify(msg.decoded_message, null, 2)}
                                            </pre>
                                          </Box>
                                        )}
                                      </Box>
                                    }
                                  />
                                </ListItem>
                              ))}
                          </List>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  </Box>
                </TabPanel>
              </Box>
            </Paper>
          ) : (
            <Paper sx={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <Box sx={{ textAlign: 'center' }}>
                <NetworkIcon sx={{ fontSize: 80, color: 'text.secondary', mb: 2 }} />
                <Typography variant="h6" color="text.secondary">
                  Select a proxy or create a new one
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Configure proxy instances to intercept traffic between components
                </Typography>
                <Button
                  variant="contained"
                  startIcon={<AddIcon />}
                  onClick={() => setNewProxyOpen(true)}
                  sx={{ mt: 2 }}
                >
                  Create New Proxy
                </Button>
              </Box>
            </Paper>
          )}
        </Grid>
      </Grid>

      {/* New Proxy Dialog */}
      <Dialog open={newProxyOpen} onClose={() => setNewProxyOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Create New Proxy</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Proxy ID"
              value={newProxy.proxy_id}
              onChange={(e) => setNewProxy({ ...newProxy, proxy_id: e.target.value })}
              fullWidth
              helperText="Unique identifier for this proxy instance"
            />
            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Listen Host"
                  value={newProxy.listen_host}
                  onChange={(e) => setNewProxy({ ...newProxy, listen_host: e.target.value })}
                  fullWidth
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Listen Port"
                  type="number"
                  value={newProxy.listen_port}
                  onChange={(e) => setNewProxy({ ...newProxy, listen_port: parseInt(e.target.value) })}
                  fullWidth
                />
              </Grid>
            </Grid>
            <Grid container spacing={2}>
              <Grid item xs={8}>
                <TextField
                  label="Target Host"
                  value={newProxy.target_host}
                  onChange={(e) => setNewProxy({ ...newProxy, target_host: e.target.value })}
                  fullWidth
                />
              </Grid>
              <Grid item xs={4}>
                <TextField
                  label="Target Port"
                  type="number"
                  value={newProxy.target_port}
                  onChange={(e) => setNewProxy({ ...newProxy, target_port: parseInt(e.target.value) })}
                  fullWidth
                />
              </Grid>
            </Grid>
            <FormControl fullWidth>
              <InputLabel>Mode</InputLabel>
              <Select
                value={newProxy.mode}
                label="Mode"
                onChange={(e) => setNewProxy({ ...newProxy, mode: e.target.value })}
              >
                <MenuItem value="passthrough">Passthrough (observe only)</MenuItem>
                <MenuItem value="intercept">Intercept (hold for review)</MenuItem>
                <MenuItem value="auto_modify">Auto Modify (apply rules)</MenuItem>
              </Select>
            </FormControl>
            <FormControlLabel
              control={
                <Switch
                  checked={newProxy.tls_enabled}
                  onChange={(e) => setNewProxy({ ...newProxy, tls_enabled: e.target.checked })}
                />
              }
              label="Enable TLS (HTTPS)"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewProxyOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreateProxy}
            disabled={!newProxy.proxy_id || loading}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* New Rule Dialog */}
      <Dialog open={newRuleOpen} onClose={() => setNewRuleOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Add Interception Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Rule Name"
              value={newRule.name || ''}
              onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
              fullWidth
            />

            <Divider>Rule Settings</Divider>

            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="Group"
                  value={newRule.group || ''}
                  onChange={(e) => setNewRule({ ...newRule, group: e.target.value })}
                  fullWidth
                  placeholder="e.g., auth, cache, headers"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Priority"
                  type="number"
                  value={newRule.priority ?? ''}
                  onChange={(e) => setNewRule({ ...newRule, priority: parseInt(e.target.value) || undefined })}
                  fullWidth
                  placeholder="Lower runs first"
                />
              </Grid>
            </Grid>
            
            <Divider>Match Conditions</Divider>
            
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={newRule.match_direction || 'both'}
                    label="Direction"
                    onChange={(e) => setNewRule({ ...newRule, match_direction: e.target.value as any })}
                  >
                    <MenuItem value="request">Request</MenuItem>
                    <MenuItem value="response">Response</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Host (regex)"
                  value={newRule.match_host || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_host: e.target.value })}
                  fullWidth
                  placeholder="e.g., api\.example\.com"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Path (regex)"
                  value={newRule.match_path || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_path: e.target.value })}
                  fullWidth
                  placeholder="e.g., /api/v1/.*"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Method"
                  value={newRule.match_method || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_method: e.target.value })}
                  fullWidth
                  placeholder="e.g., POST"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Content-Type"
                  value={newRule.match_content_type || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_content_type: e.target.value })}
                  fullWidth
                  placeholder="e.g., application/json"
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Match Status Code"
                  type="number"
                  value={newRule.match_status_code || ''}
                  onChange={(e) => setNewRule({ ...newRule, match_status_code: parseInt(e.target.value) || undefined })}
                  fullWidth
                  placeholder="e.g., 200"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  label="Match Query (JSON)"
                  value={ruleMatchQueryInput}
                  onChange={(e) => setRuleMatchQueryInput(e.target.value)}
                  fullWidth
                  multiline
                  minRows={2}
                  placeholder='{"userId": "123"}'
                />
              </Grid>
            </Grid>

            <Divider>Action</Divider>

            <FormControl fullWidth>
              <InputLabel>Action</InputLabel>
              <Select
                value={newRule.action || 'modify'}
                label="Action"
                onChange={(e) => setNewRule({ ...newRule, action: e.target.value as any })}
              >
                <MenuItem value="modify">Modify</MenuItem>
                <MenuItem value="drop">Drop</MenuItem>
                <MenuItem value="delay">Delay</MenuItem>
              </Select>
            </FormControl>

            {newRule.action === 'delay' && (
              <TextField
                label="Delay (ms)"
                type="number"
                value={newRule.delay_ms || 0}
                onChange={(e) => setNewRule({ ...newRule, delay_ms: parseInt(e.target.value) })}
                fullWidth
              />
            )}

            {newRule.action === 'modify' && (
              <>
                <Alert severity="info" sx={{ mt: 1 }}>
                  Use JSON for headers and transforms. Empty fields are ignored.
                </Alert>
                <Grid container spacing={2} sx={{ mt: 0 }}>
                  <Grid item xs={6}>
                    <TextField
                      label="Modify Path"
                      value={newRule.modify_path || ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_path: e.target.value })}
                      fullWidth
                      placeholder="/new/path"
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <TextField
                      label="Modify Status Code"
                      type="number"
                      value={newRule.modify_status_code ?? ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_status_code: parseInt(e.target.value) || undefined })}
                      fullWidth
                      placeholder="e.g., 302"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Modify Headers (JSON)"
                      value={ruleModifyHeadersInput}
                      onChange={(e) => setRuleModifyHeadersInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='{"X-Debug": "true"}'
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Remove Headers (comma-separated)"
                      value={ruleRemoveHeadersInput}
                      onChange={(e) => setRuleRemoveHeadersInput(e.target.value)}
                      fullWidth
                      placeholder="Authorization, Cookie"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Modify Body"
                      value={newRule.modify_body || ''}
                      onChange={(e) => setNewRule({ ...newRule, modify_body: e.target.value })}
                      fullWidth
                      multiline
                      minRows={3}
                      placeholder="Raw body replacement"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="Body Find/Replace (JSON)"
                      value={ruleBodyFindReplaceInput}
                      onChange={(e) => setRuleBodyFindReplaceInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='{"foo": "bar"}'
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={Boolean(newRule.body_find_replace_regex)}
                          onChange={(e) => setNewRule({ ...newRule, body_find_replace_regex: e.target.checked })}
                        />
                      }
                      label="Use regex for body find/replace"
                    />
                  </Grid>
                  <Grid item xs={12}>
                    <TextField
                      label="JSON Path Edits (JSON array)"
                      value={ruleJsonPathEditsInput}
                      onChange={(e) => setRuleJsonPathEditsInput(e.target.value)}
                      fullWidth
                      multiline
                      minRows={2}
                      placeholder='[{"path": "$.data.id", "op": "set", "value": "123"}]'
                    />
                  </Grid>
                </Grid>
              </>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewRuleOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddRule}
            disabled={!newRule.name}
          >
            Add Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Sessions Dialog */}
      <Dialog open={sessionsOpen} onClose={() => setSessionsOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Traffic Sessions</DialogTitle>
        <DialogContent dividers>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
              <TextField
                label="Session name"
                value={sessionName}
                onChange={(e) => setSessionName(e.target.value)}
                fullWidth
                placeholder="e.g., Login flow"
              />
              <Button
                variant="contained"
                onClick={handleCreateSession}
                disabled={sessionsLoading || !selectedProxy}
              >
                Save
              </Button>
            </Box>

            <Divider />

            {sessionsLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress size={24} />
              </Box>
            ) : sessions.length === 0 ? (
              <Alert severity="info">No saved sessions yet.</Alert>
            ) : (
              <List>
                {sessions.map((session) => (
                  <ListItem
                    key={session.id}
                    secondaryAction={
                      <Button
                        size="small"
                        onClick={() => handleLoadSession(session.id)}
                      >
                        Load
                      </Button>
                    }
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle2">{session.name}</Typography>
                          {activeSession?.id === session.id && (
                            <Chip label="Active" size="small" color="info" />
                          )}
                        </Box>
                      }
                      secondary={`${session.entries} entries - ${new Date(session.created_at).toLocaleString()}`}
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSessionsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Traffic Detail Dialog */}
      <Dialog open={trafficDetailOpen} onClose={() => setTrafficDetailOpen(false)} maxWidth="lg" fullWidth>
        <DialogTitle>
          Traffic Details
          {selectedTraffic?.modified && (
            <Chip label="Modified" size="small" color="warning" sx={{ ml: 2 }} />
          )}
        </DialogTitle>
        <DialogContent dividers>
          {selectedTraffic && (
            <Grid container spacing={2}>
              {/* Request */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Request</Typography>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="subtitle2" color="primary">
                    {selectedTraffic.request.method} {selectedTraffic.request.path}
                  </Typography>
                  {selectedTraffic.request.url && (
                    <Typography variant="caption" color="text.secondary" display="block">
                      {selectedTraffic.request.url}
                    </Typography>
                  )}
                  
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                    Headers
                  </Typography>
                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                    <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                      {JSON.stringify(selectedTraffic.request.headers, null, 2)}
                    </pre>
                  </Box>

                  {(selectedTraffic.request.body || selectedTraffic.request.body_text) && (
                    <>
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                        Body
                      </Typography>
                      <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                        <pre style={{ margin: 0, fontSize: '12px' }}>
                          {selectedTraffic.request.body || selectedTraffic.request.body_text}
                        </pre>
                      </Box>
                    </>
                  )}
                </Paper>
              </Grid>

              {/* Response */}
              <Grid item xs={12} md={6}>
                <Typography variant="h6" gutterBottom>Response</Typography>
                {selectedTraffic.response ? (
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Chip
                        label={selectedTraffic.response.status_code}
                        color={
                          selectedTraffic.response.status_code < 300 ? 'success' :
                          selectedTraffic.response.status_code < 400 ? 'info' :
                          selectedTraffic.response.status_code < 500 ? 'warning' : 'error'
                        }
                      />
                      <Typography>{selectedTraffic.response.status_text || selectedTraffic.response.status_message}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        ({Math.round(selectedTraffic.duration_ms || 0)}ms)
                      </Typography>
                    </Box>

                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                      Headers
                    </Typography>
                    <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                      <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                        {JSON.stringify(selectedTraffic.response.headers, null, 2)}
                      </pre>
                    </Box>

                    {(selectedTraffic.response.body || selectedTraffic.response.body_text) && (
                      <>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                          Body
                        </Typography>
                        <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                          <pre style={{ margin: 0, fontSize: '12px' }}>
                            {selectedTraffic.response.body || selectedTraffic.response.body_text}
                          </pre>
                        </Box>
                      </>
                    )}
                  </Paper>
                ) : (
                  <Alert severity="warning">Response not received yet</Alert>
                )}
              </Grid>

              {/* Rules Applied */}
              {selectedTraffic.rules_applied && selectedTraffic.rules_applied.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom>Rules Applied</Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {selectedTraffic.rules_applied.map((rule, i) => (
                      <Chip key={i} label={rule} color="warning" />
                    ))}
                  </Box>
                </Grid>
              )}

              {/* Traffic Diff Viewer (for modified traffic) */}
              {selectedTraffic.modified && (
                <Grid item xs={12}>
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SwapIcon /> Traffic Diff
                    <FormControl size="small" sx={{ ml: 'auto' }}>
                      <Select
                        value={diffViewMode}
                        onChange={(e) => setDiffViewMode(e.target.value as 'unified' | 'side-by-side')}
                        size="small"
                      >
                        <MenuItem value="side-by-side">Side by Side</MenuItem>
                        <MenuItem value="unified">Unified</MenuItem>
                      </Select>
                    </FormControl>
                  </Typography>
                  
                  {diffLoading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                      <CircularProgress size={24} />
                    </Box>
                  ) : trafficDiff ? (
                    <Box>
                      {/* Request Headers Diff */}
                      {trafficDiff.request_diff?.headers_diff && (
                        <Accordion defaultExpanded>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Request Headers
                              {trafficDiff.request_diff.headers_diff.changes?.length > 0 && (
                                <Chip label={trafficDiff.request_diff.headers_diff.changes.length} size="small" color="warning" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            {diffViewMode === 'unified' ? (
                              <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem' }}>
                                {trafficDiff.request_diff.headers_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                  <Box 
                                    key={i}
                                    sx={{ 
                                      color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                      bgcolor: line.startsWith('+') ? 'rgba(76,175,80,0.1)' : line.startsWith('-') ? 'rgba(244,67,54,0.1)' : 'transparent',
                                    }}
                                  >
                                    {line}
                                  </Box>
                                ))}
                              </Box>
                            ) : (
                              <Grid container spacing={1}>
                                <Grid item xs={6}>
                                  <Typography variant="caption" color="text.secondary">Original</Typography>
                                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                                    <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', color: '#f44336' }}>
                                      {trafficDiff.request_diff.headers_diff.original && JSON.stringify(trafficDiff.request_diff.headers_diff.original, null, 2)}
                                    </pre>
                                  </Box>
                                </Grid>
                                <Grid item xs={6}>
                                  <Typography variant="caption" color="text.secondary">Modified</Typography>
                                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                                    <pre style={{ margin: 0, fontSize: '11px', overflow: 'auto', color: '#4caf50' }}>
                                      {trafficDiff.request_diff.headers_diff.modified && JSON.stringify(trafficDiff.request_diff.headers_diff.modified, null, 2)}
                                    </pre>
                                  </Box>
                                </Grid>
                              </Grid>
                            )}
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Request Body Diff */}
                      {trafficDiff.request_diff?.body_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Request Body
                              {trafficDiff.request_diff.body_diff.has_changes && (
                                <Chip label="Changed" size="small" color="warning" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', maxHeight: 200, overflow: 'auto' }}>
                              {trafficDiff.request_diff.body_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Response Headers Diff */}
                      {trafficDiff.response_diff?.headers_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Response Headers
                              {trafficDiff.response_diff.headers_diff.changes?.length > 0 && (
                                <Chip label={trafficDiff.response_diff.headers_diff.changes.length} size="small" color="info" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem' }}>
                              {trafficDiff.response_diff.headers_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}

                      {/* Response Body Diff */}
                      {trafficDiff.response_diff?.body_diff && (
                        <Accordion>
                          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                            <Typography variant="subtitle2">
                              Response Body
                              {trafficDiff.response_diff.body_diff.has_changes && (
                                <Chip label="Changed" size="small" color="info" sx={{ ml: 1 }} />
                              )}
                            </Typography>
                          </AccordionSummary>
                          <AccordionDetails>
                            <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, fontFamily: 'monospace', fontSize: '0.75rem', maxHeight: 200, overflow: 'auto' }}>
                              {trafficDiff.response_diff.body_diff.unified_diff?.split('\n').map((line: string, i: number) => (
                                <Box 
                                  key={i}
                                  sx={{ 
                                    color: line.startsWith('+') ? '#4caf50' : line.startsWith('-') ? '#f44336' : '#e0e0e0',
                                  }}
                                >
                                  {line}
                                </Box>
                              ))}
                            </Box>
                          </AccordionDetails>
                        </Accordion>
                      )}
                    </Box>
                  ) : (
                    <Alert severity="info">
                      No diff data available. The traffic may have been modified without storing the original.
                    </Alert>
                  )}
                </Grid>
              )}

              <Grid item xs={12}>
                <Typography variant="h6" gutterBottom>Notes & Tags</Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label="Notes"
                    multiline
                    minRows={2}
                    value={trafficNotes}
                    onChange={(e) => setTrafficNotes(e.target.value)}
                    placeholder="Add investigation notes or findings"
                  />
                  <TextField
                    label="Tags"
                    value={trafficTagsInput}
                    onChange={(e) => setTrafficTagsInput(e.target.value)}
                    placeholder="Comma-separated tags"
                  />
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Button
                      variant="contained"
                      startIcon={savingTrafficMeta ? <CircularProgress size={16} color="inherit" /> : <CheckIcon />}
                      onClick={handleSaveTrafficMeta}
                      disabled={savingTrafficMeta}
                    >
                      Save Notes
                    </Button>
                    {selectedTraffic.tags && selectedTraffic.tags.length > 0 && (
                      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
                        {selectedTraffic.tags.map((tag, index) => (
                          <Chip key={index} label={tag} size="small" />
                        ))}
                      </Box>
                    )}
                  </Box>
                </Box>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<ReplayIcon />}
            onClick={() => selectedTraffic && handleOpenReplay(selectedTraffic)}
            disabled={!selectedTraffic}
          >
            Replay
          </Button>
          <Button
            startIcon={<CopyIcon />}
            onClick={() => copyToClipboard(JSON.stringify(selectedTraffic, null, 2))}
          >
            Copy JSON
          </Button>
          <Button onClick={() => setTrafficDetailOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Replay Dialog */}
      <Dialog open={replayOpen} onClose={() => setReplayOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Replay Request</DialogTitle>
        <DialogContent dividers>
          {replayEntry && (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Alert severity="info">
                Replaying {replayEntry.request.method} {replayEntry.request.path}
              </Alert>
              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    label="Method"
                    value={replayOverrides.method}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, method: e.target.value })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Path"
                    value={replayOverrides.path}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, path: e.target.value })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Base URL (optional)"
                    value={replayOverrides.baseUrl}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, baseUrl: e.target.value })}
                    fullWidth
                    placeholder="https://api.example.com"
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    label="Timeout (seconds)"
                    type="number"
                    value={replayOverrides.timeout}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, timeout: parseInt(e.target.value) || 0 })}
                    fullWidth
                  />
                </Grid>
                <Grid item xs={6}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={replayOverrides.verifyTls}
                        onChange={(e) => setReplayOverrides({ ...replayOverrides, verifyTls: e.target.checked })}
                      />
                    }
                    label="Verify TLS"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Add Headers (JSON)"
                    value={replayOverrides.addHeaders}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, addHeaders: e.target.value })}
                    fullWidth
                    multiline
                    minRows={2}
                    placeholder='{"X-Replay": "true"}'
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Remove Headers (comma-separated)"
                    value={replayOverrides.removeHeaders}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, removeHeaders: e.target.value })}
                    fullWidth
                    placeholder="Authorization, Cookie"
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    label="Body"
                    value={replayOverrides.body}
                    onChange={(e) => setReplayOverrides({ ...replayOverrides, body: e.target.value })}
                    fullWidth
                    multiline
                    minRows={3}
                  />
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setReplayOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleReplayRequest}
            disabled={replayLoading || !replayEntry}
          >
            {replayLoading ? 'Replaying...' : 'Replay'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Guided Wizard Dialog */}
      <Dialog open={wizardOpen} onClose={() => setWizardOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TutorialIcon color="info" />
          <Box>
            <Typography variant="h6">Getting Started with MITM Workbench</Typography>
            <Typography variant="body2" color="text.secondary">
              {guidedSetup?.description || 'A step-by-step guide to help you get started'}
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {loadingGuide ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : guidedSetup ? (
            <Box>
              <Box sx={{ mb: 3, display: 'flex', gap: 2 }}>
                <Chip 
                  icon={<TipIcon />} 
                  label={`Difficulty: ${guidedSetup.difficulty}`} 
                  color="primary" 
                  variant="outlined" 
                />
                <Chip 
                  icon={<SpeedIcon />} 
                  label={`Est. Time: ${guidedSetup.estimated_time}`} 
                  color="secondary" 
                  variant="outlined" 
                />
              </Box>

              <Stepper activeStep={wizardStep} orientation="vertical">
                {guidedSetup.steps.map((step, index) => (
                  <Step key={index}>
                    <StepLabel>
                      <Typography variant="subtitle1">{step.title}</Typography>
                    </StepLabel>
                    <StepContent>
                      <Typography variant="body2" paragraph>
                        {step.description}
                      </Typography>

                      {/* Tips */}
                      {step.tips && step.tips.length > 0 && (
                        <Alert severity="info" sx={{ mb: 2 }} icon={<TipIcon />}>
                          <Typography variant="subtitle2">Tips:</Typography>
                          <ul style={{ margin: '8px 0', paddingLeft: 20 }}>
                            {step.tips.map((tip, i) => (
                              <li key={i}><Typography variant="body2">{tip}</Typography></li>
                            ))}
                          </ul>
                        </Alert>
                      )}

                      {/* Fields */}
                      {step.fields && Object.keys(step.fields).length > 0 && (
                        <Box sx={{ mb: 2, bgcolor: 'background.default', p: 2, borderRadius: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>Configuration Fields:</Typography>
                          {Object.entries(step.fields).map(([field, desc]) => (
                            <Box key={field} sx={{ display: 'flex', gap: 1, mb: 0.5 }}>
                              <Chip label={field} size="small" color="primary" />
                              <Typography variant="body2">{desc}</Typography>
                            </Box>
                          ))}
                        </Box>
                      )}

                      {/* Modes */}
                      {step.modes && step.modes.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Available Modes:</Typography>
                          <Grid container spacing={1}>
                            {step.modes.map((mode, i) => (
                              <Grid item xs={12} sm={4} key={i}>
                                <Card variant="outlined" sx={{ p: 1.5 }}>
                                  <Typography variant="subtitle2" color="primary">{mode.name}</Typography>
                                  <Typography variant="caption" display="block">{mode.description}</Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    Use case: {mode.use_case}
                                  </Typography>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}

                      {/* Examples */}
                      {step.examples && step.examples.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Configuration Examples:</Typography>
                          {step.examples.map((example, i) => (
                            <Accordion key={i} sx={{ mb: 1 }}>
                              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                <Chip label={example.type} size="small" sx={{ mr: 1 }} />
                                <Typography variant="body2">How to configure {example.type}</Typography>
                              </AccordionSummary>
                              <AccordionDetails>
                                <Box sx={{ bgcolor: 'grey.900', p: 2, borderRadius: 1 }}>
                                  <pre style={{ margin: 0, fontSize: '12px', whiteSpace: 'pre-wrap' }}>
                                    {example.instructions}
                                  </pre>
                                </Box>
                              </AccordionDetails>
                            </Accordion>
                          ))}
                        </Box>
                      )}

                      {/* Presets */}
                      {step.presets && step.presets.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Available Presets:</Typography>
                          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                            {step.presets.map((preset, i) => (
                              <Tooltip key={i} title={preset.description}>
                                <Chip label={preset.name} variant="outlined" />
                              </Tooltip>
                            ))}
                          </Box>
                        </Box>
                      )}

                      {/* Export formats */}
                      {step.formats && step.formats.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" gutterBottom>Export Formats:</Typography>
                          <Grid container spacing={1}>
                            {step.formats.map((fmt, i) => (
                              <Grid item xs={12} sm={4} key={i}>
                                <Card variant="outlined" sx={{ p: 1.5, textAlign: 'center' }}>
                                  {fmt.format === 'PDF' && <PdfIcon color="error" />}
                                  {fmt.format === 'Markdown' && <MarkdownIcon color="info" />}
                                  {fmt.format === 'Word' && <WordIcon color="primary" />}
                                  <Typography variant="subtitle2">{fmt.format}</Typography>
                                  <Typography variant="caption">{fmt.description}</Typography>
                                </Card>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}

                      <Box sx={{ mt: 2, display: 'flex', gap: 1 }}>
                        <Button
                          disabled={index === 0}
                          onClick={() => setWizardStep(index - 1)}
                          startIcon={<BackIcon />}
                        >
                          Back
                        </Button>
                        <Button
                          variant="contained"
                          onClick={() => {
                            if (index === guidedSetup.steps.length - 1) {
                              setWizardOpen(false);
                              setNewProxyOpen(true);
                            } else {
                              setWizardStep(index + 1);
                            }
                          }}
                          endIcon={<NextIcon />}
                        >
                          {index === guidedSetup.steps.length - 1 ? 'Create Your First Proxy' : 'Continue'}
                        </Button>
                      </Box>
                    </StepContent>
                  </Step>
                ))}
              </Stepper>

              {/* Common Use Cases */}
              {guidedSetup.common_use_cases && guidedSetup.common_use_cases.length > 0 && (
                <Box sx={{ mt: 4 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <IdeaIcon color="warning" /> Common Use Cases
                  </Typography>
                  <Grid container spacing={2}>
                    {guidedSetup.common_use_cases.map((useCase, index) => (
                      <Grid item xs={12} md={6} key={index}>
                        <Card variant="outlined">
                          <CardContent>
                            <Typography variant="subtitle1" color="primary" gutterBottom>
                              {useCase.title}
                            </Typography>
                            <Typography variant="body2" paragraph>
                              {useCase.description}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">Steps:</Typography>
                            <ol style={{ margin: '4px 0', paddingLeft: 20 }}>
                              {useCase.steps.map((s, i) => (
                                <li key={i}><Typography variant="caption">{s}</Typography></li>
                              ))}
                            </ol>
                          </CardContent>
                        </Card>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              )}

              {/* Troubleshooting */}
              {guidedSetup.troubleshooting && guidedSetup.troubleshooting.length > 0 && (
                <Box sx={{ mt: 4 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <DebugIcon color="error" /> Troubleshooting
                  </Typography>
                  {guidedSetup.troubleshooting.map((item, index) => (
                    <Accordion key={index}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography color="error">{item.issue}</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <ul style={{ margin: 0, paddingLeft: 20 }}>
                          {item.solutions.map((sol, i) => (
                            <li key={i}><Typography variant="body2">{sol}</Typography></li>
                          ))}
                        </ul>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Box>
              )}
            </Box>
          ) : (
            <Alert severity="warning">
              Failed to load guided setup. Please try again.
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWizardOpen(false)}>Close</Button>
          <Button 
            variant="contained" 
            onClick={() => { setWizardOpen(false); setNewProxyOpen(true); }}
            startIcon={<AddIcon />}
          >
            Create Proxy Now
          </Button>
        </DialogActions>
      </Dialog>

      {/* Test Scenarios Dialog */}
      <Dialog 
        open={scenarioDialogOpen} 
        onClose={() => setScenarioDialogOpen(false)} 
        maxWidth="lg" 
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <ScienceIcon color="warning" />
          <Box>
            <Typography variant="h6">Security Test Scenarios</Typography>
            <Typography variant="body2" color="text.secondary">
              Pre-built scenarios to learn security testing - just click and run!
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent dividers>
          {!selectedProxy && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              <AlertTitle>Create a Proxy First</AlertTitle>
              You need to create and select a proxy before running test scenarios.
              <Button 
                size="small" 
                sx={{ ml: 2 }} 
                onClick={() => { setScenarioDialogOpen(false); setNewProxyOpen(true); }}
              >
                Create Proxy
              </Button>
            </Alert>
          )}

          {scenarioResult && (
            <Alert severity="success" sx={{ mb: 2 }} onClose={() => setScenarioResult(null)}>
              <AlertTitle>✅ {scenarioResult.message}</AlertTitle>
              <Typography variant="body2">
                {scenarioResult.rules_added} rules added. Mode set to: {scenarioResult.mode}
              </Typography>
              <Box sx={{ mt: 1 }}>
                <Typography variant="caption" fontWeight="bold">Next Steps:</Typography>
                <ul style={{ margin: '4px 0', paddingLeft: 20 }}>
                  {scenarioResult.next_steps?.map((step: string, i: number) => (
                    <li key={i}><Typography variant="caption">{step}</Typography></li>
                  ))}
                </ul>
              </Box>
            </Alert>
          )}

          <Grid container spacing={2}>
            {testScenarios.map((scenario) => (
              <Grid item xs={12} sm={6} md={4} key={scenario.id}>
                <Card 
                  sx={{ 
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    transition: 'transform 0.2s, box-shadow 0.2s',
                    '&:hover': {
                      transform: 'translateY(-4px)',
                      boxShadow: 4,
                    },
                    border: selectedScenario?.id === scenario.id ? `2px solid ${theme.palette.primary.main}` : undefined,
                  }}
                >
                  <CardContent sx={{ flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                      <Avatar sx={{ bgcolor: 'warning.main', width: 36, height: 36 }}>
                        {scenario.icon === 'security' && <SecurityIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'lock_open' && <LockOpenIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'public' && <NetworkIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'remove_circle' && <CancelIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'edit' && <EditIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'speed' && <SpeedIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'code' && <CodeIcon sx={{ fontSize: 20 }} />}
                        {scenario.icon === 'visibility' && <ViewIcon sx={{ fontSize: 20 }} />}
                        {!['security', 'lock_open', 'public', 'remove_circle', 'edit', 'speed', 'code', 'visibility'].includes(scenario.icon) && <ScienceIcon sx={{ fontSize: 20 }} />}
                      </Avatar>
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="subtitle1" fontWeight="bold" sx={{ lineHeight: 1.2 }}>
                          {scenario.name}
                        </Typography>
                        <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5 }}>
                          <Chip 
                            label={scenario.difficulty} 
                            size="small" 
                            color={getDifficultyColor(scenario.difficulty) as any}
                            sx={{ height: 18, fontSize: '0.65rem' }}
                          />
                          <Chip 
                            label={scenario.estimated_time} 
                            size="small" 
                            variant="outlined"
                            sx={{ height: 18, fontSize: '0.65rem' }}
                          />
                        </Box>
                      </Box>
                    </Box>
                    
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2, minHeight: 40 }}>
                      {scenario.description}
                    </Typography>

                    <Typography variant="caption" fontWeight="bold" color="text.secondary">
                      What to look for:
                    </Typography>
                    <ul style={{ margin: '4px 0', paddingLeft: 16 }}>
                      {scenario.what_to_look_for.slice(0, 2).map((item, i) => (
                        <li key={i}>
                          <Typography variant="caption" color="text.secondary">{item}</Typography>
                        </li>
                      ))}
                    </ul>
                  </CardContent>
                  <CardActions sx={{ p: 2, pt: 0 }}>
                    <Button
                      variant="contained"
                      size="small"
                      fullWidth
                      startIcon={runningScenario ? <CircularProgress size={16} color="inherit" /> : <RunIcon />}
                      onClick={() => handleRunScenario(scenario.id)}
                      disabled={!selectedProxy || runningScenario}
                    >
                      {runningScenario ? 'Running...' : 'Run Scenario'}
                    </Button>
                    <Tooltip title="View details">
                      <IconButton size="small" onClick={() => setSelectedScenario(scenario)}>
                        <InfoIcon />
                      </IconButton>
                    </Tooltip>
                  </CardActions>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Scenario Detail Panel */}
          {selectedScenario && (
            <Paper sx={{ mt: 3, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
                <Typography variant="h6">{selectedScenario.name}</Typography>
                <IconButton size="small" onClick={() => setSelectedScenario(null)}>
                  <CloseIcon />
                </IconButton>
              </Box>
              
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <ViewIcon fontSize="small" /> What to Look For
                  </Typography>
                  <List dense>
                    {selectedScenario.what_to_look_for.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <DotIcon sx={{ fontSize: 8 }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: 'body2' }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <LearnIcon fontSize="small" /> Learning Points
                  </Typography>
                  <List dense>
                    {selectedScenario.learning_points.map((item, i) => (
                      <ListItem key={i} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <TipIcon sx={{ fontSize: 14, color: 'warning.main' }} />
                        </ListItemIcon>
                        <ListItemText primary={item} primaryTypographyProps={{ variant: 'body2' }} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              </Grid>

              {selectedScenario.rules.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <RuleIcon fontSize="small" /> Rules Applied ({selectedScenario.rules.length})
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                    {selectedScenario.rules.map((rule, i) => (
                      <Chip 
                        key={i}
                        label={rule.name || `Rule ${i + 1}`}
                        size="small"
                        variant="outlined"
                        color="warning"
                      />
                    ))}
                  </Box>
                </Box>
              )}
            </Paper>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setScenarioDialogOpen(false)}>Close</Button>
          {selectedProxy && selectedScenario && (
            <Button
              variant="contained"
              startIcon={runningScenario ? <CircularProgress size={16} color="inherit" /> : <RunIcon />}
              onClick={() => handleRunScenario(selectedScenario.id)}
              disabled={runningScenario}
            >
              Run "{selectedScenario.name}"
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* WebSocket Rule Dialog */}
      <Dialog open={wsNewRuleOpen} onClose={() => setWsNewRuleOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Add WebSocket Rule</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Rule Name"
              value={wsNewRule.name || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, name: e.target.value })}
              fullWidth
              placeholder="e.g., Block Binary Messages"
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={wsNewRule.match_direction || 'both'}
                    label="Direction"
                    onChange={(e) => setWsNewRule({ ...wsNewRule, match_direction: e.target.value })}
                  >
                    <MenuItem value="client_to_server">Client → Server</MenuItem>
                    <MenuItem value="server_to_client">Server → Client</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Action</InputLabel>
                  <Select
                    value={wsNewRule.action || 'passthrough'}
                    label="Action"
                    onChange={(e) => setWsNewRule({ ...wsNewRule, action: e.target.value })}
                  >
                    <MenuItem value="passthrough">Passthrough</MenuItem>
                    <MenuItem value="modify">Modify</MenuItem>
                    <MenuItem value="drop">Drop</MenuItem>
                    <MenuItem value="delay">Delay</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <TextField
              label="Match Payload Pattern (regex)"
              value={wsNewRule.match_payload_pattern || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, match_payload_pattern: e.target.value })}
              fullWidth
              placeholder="e.g., .*login.*"
            />
            <TextField
              label="Match JSON Path"
              value={wsNewRule.match_json_path || ''}
              onChange={(e) => setWsNewRule({ ...wsNewRule, match_json_path: e.target.value })}
              fullWidth
              placeholder="e.g., $.type"
              helperText="JSONPath expression to match in JSON payloads"
            />
            {wsNewRule.action === 'delay' && (
              <TextField
                label="Delay (ms)"
                type="number"
                value={wsNewRule.delay_ms || 0}
                onChange={(e) => setWsNewRule({ ...wsNewRule, delay_ms: parseInt(e.target.value) || 0 })}
                fullWidth
              />
            )}
            <TextField
              label="Priority"
              type="number"
              value={wsNewRule.priority || 0}
              onChange={(e) => setWsNewRule({ ...wsNewRule, priority: parseInt(e.target.value) || 0 })}
              fullWidth
              helperText="Lower values run first"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={wsNewRule.enabled !== false}
                  onChange={(e) => setWsNewRule({ ...wsNewRule, enabled: e.target.checked })}
                />
              }
              label="Enabled"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWsNewRuleOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleAddWebSocketRule}
            disabled={!wsNewRule.name || loading}
          >
            Add Rule
          </Button>
        </DialogActions>
      </Dialog>

      {/* Certificate Generation Dialog */}
      <Dialog open={showCertGenDialog} onClose={() => setShowCertGenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Generate CA Certificate</DialogTitle>
        <DialogContent>
          <Alert severity="warning" sx={{ mb: 2, mt: 1 }}>
            Generating a new CA certificate will invalidate all existing host certificates. 
            Users will need to reinstall the new CA certificate.
          </Alert>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Common Name"
              value={certGenConfig.common_name}
              onChange={(e) => setCertGenConfig({ ...certGenConfig, common_name: e.target.value })}
              fullWidth
            />
            <TextField
              label="Organization"
              value={certGenConfig.organization}
              onChange={(e) => setCertGenConfig({ ...certGenConfig, organization: e.target.value })}
              fullWidth
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <TextField
                  label="Country Code"
                  value={certGenConfig.country}
                  onChange={(e) => setCertGenConfig({ ...certGenConfig, country: e.target.value })}
                  fullWidth
                  inputProps={{ maxLength: 2 }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  label="Validity (days)"
                  type="number"
                  value={certGenConfig.validity_days}
                  onChange={(e) => setCertGenConfig({ ...certGenConfig, validity_days: parseInt(e.target.value) || 365 })}
                  fullWidth
                />
              </Grid>
            </Grid>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCertGenDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleGenerateCACertificate}
            disabled={certGenerating}
            startIcon={certGenerating ? <CircularProgress size={16} /> : null}
          >
            {certGenerating ? 'Generating...' : 'Generate'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Certificate Installation Instructions Dialog */}
      <Dialog open={showCertInstallDialog} onClose={() => setShowCertInstallDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Certificate Installation Guide</DialogTitle>
        <DialogContent>
          {certInstallInstructions ? (
            <Box>
              <Alert severity="info" sx={{ mb: 2 }}>
                Install the CA certificate to trust HTTPS connections intercepted by the MITM proxy.
              </Alert>
              
              <Typography variant="subtitle2" gutterBottom>Certificate Details</Typography>
              <Paper sx={{ p: 2, mb: 2, bgcolor: 'background.default' }}>
                <Typography variant="body2"><strong>Name:</strong> {certInstallInstructions.ca_certificate.common_name}</Typography>
                <Typography variant="body2"><strong>Valid Until:</strong> {certInstallInstructions.ca_certificate.valid_until}</Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>
                  <strong>Fingerprint:</strong> {certInstallInstructions.ca_certificate.fingerprint}
                </Typography>
              </Paper>

              <Typography variant="subtitle2" gutterBottom>Installation Instructions</Typography>
              {Object.entries(certInstallInstructions.instructions).map(([platform, info]) => (
                <Accordion key={platform}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography>{info.title}</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {info.steps.map((step, idx) => (
                        <ListItem key={idx}>
                          <ListItemIcon>
                            <Chip label={idx + 1} size="small" />
                          </ListItemIcon>
                          <ListItemText primary={step} />
                        </ListItem>
                      ))}
                    </List>
                    {info.command && (
                      <Paper sx={{ p: 1, bgcolor: 'grey.900', mt: 1 }}>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', color: 'grey.100' }}>
                          {info.command}
                        </Typography>
                        <IconButton 
                          size="small" 
                          onClick={() => {
                            navigator.clipboard.writeText(info.command!);
                            setSuccess('Command copied to clipboard');
                          }}
                          sx={{ color: 'grey.400' }}
                        >
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Paper>
                    )}
                    {info.note && (
                      <Alert severity="info" sx={{ mt: 1 }}>
                        {info.note}
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          ) : (
            <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
              <CircularProgress />
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowCertInstallDialog(false)}>Close</Button>
          <Button 
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={() => handleDownloadCACertificate('pem')}
          >
            Download Certificate
          </Button>
        </DialogActions>
      </Dialog>

      {/* WebSocket Frame Detail Dialog */}
      <Dialog open={!!wsSelectedFrame} onClose={() => setWsSelectedFrame(null)} maxWidth="md" fullWidth>
        <DialogTitle>WebSocket Frame Details</DialogTitle>
        <DialogContent>
          {wsSelectedFrame && (
            <Box>
              <Grid container spacing={2} sx={{ mb: 2 }}>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Direction</Typography>
                  <Typography>{wsSelectedFrame.direction}</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Type</Typography>
                  <Typography>{wsSelectedFrame.opcode_name}</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Size</Typography>
                  <Typography>{wsSelectedFrame.payload_length} bytes</Typography>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Typography variant="caption" color="text.secondary">Time</Typography>
                  <Typography>{new Date(wsSelectedFrame.timestamp).toLocaleString()}</Typography>
                </Grid>
              </Grid>
              
              {wsSelectedFrame.modified && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  This frame was modified by a rule
                </Alert>
              )}

              <Typography variant="subtitle2" gutterBottom>Payload</Typography>
              {wsSelectedFrame.payload_json ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <pre style={{ margin: 0, color: '#e0e0e0', fontFamily: 'monospace', fontSize: '0.8rem' }}>
                    {JSON.stringify(wsSelectedFrame.payload_json, null, 2)}
                  </pre>
                </Paper>
              ) : wsSelectedFrame.payload_text ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <Typography sx={{ fontFamily: 'monospace', color: '#e0e0e0', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {wsSelectedFrame.payload_text}
                  </Typography>
                </Paper>
              ) : wsSelectedFrame.payload_hex ? (
                <Paper sx={{ p: 2, bgcolor: 'grey.900', maxHeight: 400, overflow: 'auto' }}>
                  <Typography sx={{ fontFamily: 'monospace', color: '#e0e0e0', wordBreak: 'break-all' }}>
                    {wsSelectedFrame.payload_hex}
                  </Typography>
                </Paper>
              ) : (
                <Typography color="text.secondary">No payload data</Typography>
              )}
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setWsSelectedFrame(null)}>Close</Button>
          {wsSelectedFrame?.payload_text && (
            <Button
              startIcon={<CopyIcon />}
              onClick={() => {
                navigator.clipboard.writeText(wsSelectedFrame.payload_text || '');
                setSuccess('Payload copied to clipboard');
              }}
            >
              Copy Payload
            </Button>
          )}
        </DialogActions>
      </Dialog>

      {/* New Template Dialog */}
      <Dialog open={showNewTemplateDialog} onClose={() => setShowNewTemplateDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>Create Custom Template</DialogTitle>
        <DialogContent>
          <Box sx={{ pt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Template Name"
              value={newTemplate.name}
              onChange={(e) => setNewTemplate({ ...newTemplate, name: e.target.value })}
              fullWidth
              required
            />
            <TextField
              label="Description"
              value={newTemplate.description}
              onChange={(e) => setNewTemplate({ ...newTemplate, description: e.target.value })}
              fullWidth
              multiline
              rows={2}
              required
            />
            <Grid container spacing={2}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Category</InputLabel>
                  <Select
                    value={newTemplate.category}
                    label="Category"
                    onChange={(e) => setNewTemplate({ ...newTemplate, category: e.target.value })}
                  >
                    <MenuItem value="Custom">Custom</MenuItem>
                    <MenuItem value="Security Testing">Security Testing</MenuItem>
                    <MenuItem value="Debugging">Debugging</MenuItem>
                    <MenuItem value="Development">Development</MenuItem>
                    <MenuItem value="API Testing">API Testing</MenuItem>
                    <MenuItem value="Mobile Testing">Mobile Testing</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Match Type</InputLabel>
                  <Select
                    value={newTemplate.match_type}
                    label="Match Type"
                    onChange={(e) => setNewTemplate({ ...newTemplate, match_type: e.target.value })}
                  >
                    <MenuItem value="header">Header</MenuItem>
                    <MenuItem value="body">Body</MenuItem>
                    <MenuItem value="url">URL</MenuItem>
                    <MenuItem value="status">Status Code</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>
            <TextField
              label="Match Pattern"
              value={newTemplate.match_pattern}
              onChange={(e) => setNewTemplate({ ...newTemplate, match_pattern: e.target.value })}
              fullWidth
              placeholder={newTemplate.is_regex ? 'Regular expression' : 'Exact match string'}
              required
            />
            <TextField
              label="Replace Pattern"
              value={newTemplate.replace_pattern}
              onChange={(e) => setNewTemplate({ ...newTemplate, replace_pattern: e.target.value })}
              fullWidth
              placeholder="Replacement text (use $1, $2 for regex groups)"
              required
            />
            <Grid container spacing={2}>
              <Grid item xs={4}>
                <FormControl fullWidth>
                  <InputLabel>Direction</InputLabel>
                  <Select
                    value={newTemplate.direction}
                    label="Direction"
                    onChange={(e) => setNewTemplate({ ...newTemplate, direction: e.target.value })}
                  >
                    <MenuItem value="request">Request</MenuItem>
                    <MenuItem value="response">Response</MenuItem>
                    <MenuItem value="both">Both</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newTemplate.is_regex}
                      onChange={(e) => setNewTemplate({ ...newTemplate, is_regex: e.target.checked })}
                    />
                  }
                  label="Use Regex"
                />
              </Grid>
              <Grid item xs={4}>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={newTemplate.case_sensitive}
                      onChange={(e) => setNewTemplate({ ...newTemplate, case_sensitive: e.target.checked })}
                    />
                  }
                  label="Case Sensitive"
                />
              </Grid>
            </Grid>
            <TextField
              label="Tags (comma-separated)"
              value={templateTagsInput}
              onChange={(e) => setTemplateTagsInput(e.target.value)}
              fullWidth
              placeholder="e.g., security, header-manipulation, auth"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowNewTemplateDialog(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleCreateTemplate}
            disabled={!newTemplate.name || !newTemplate.match_pattern || !newTemplate.replace_pattern}
          >
            Create Template
          </Button>
        </DialogActions>
      </Dialog>

      {/* Notifications */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!success}
        autoHideDuration={3000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default MITMWorkbenchPage;
