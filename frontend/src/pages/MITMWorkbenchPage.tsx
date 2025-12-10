import React, { useState, useEffect, useCallback } from 'react';
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
  Select,
  MenuItem,
  InputLabel,
  FormControl,
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
} from '@mui/icons-material';
import { mitmClient, MITMProxy, MITMTrafficEntry, MITMRule, MITMPresetRule, MITMAnalysisResult, MITMGuidedSetup, MITMTestScenario, MITMProxyHealth, NaturalLanguageRuleResponse, AISuggestion, AISuggestionsResponse } from '../api/client';

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
    headers: Record<string, string>;
    body: string;
  };
  response?: {
    status_code: number;
    status_text: string;
    headers: Record<string, string>;
    body: string;
  };
  duration_ms: number;
  modified: boolean;
  rules_applied: string[];
}

interface InterceptionRule {
  id: string;
  name: string;
  enabled: boolean;
  match_direction: 'request' | 'response' | 'both';
  match_host?: string;
  match_path?: string;
  match_method?: string;
  match_content_type?: string;
  match_status_code?: number;
  action: 'modify' | 'drop' | 'delay';
  modify_headers?: Record<string, string>;
  remove_headers?: string[];
  body_find_replace?: Record<string, string>;
  delay_ms?: number;
}

interface PresetRule {
  id: string;
  name: string;
  description?: string;
}

// Tab panel component
function TabPanel({ children, value, index }: { children: React.ReactNode; value: number; index: number }) {
  return (
    <div hidden={value !== index} style={{ height: '100%' }}>
      {value === index && <Box sx={{ p: 2, height: '100%' }}>{children}</Box>}
    </div>
  );
}

const MITMWorkbenchPage: React.FC = () => {
  // State
  const [proxies, setProxies] = useState<ProxyInstance[]>([]);
  const [selectedProxy, setSelectedProxy] = useState<string | null>(null);
  const [traffic, setTraffic] = useState<TrafficEntry[]>([]);
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

  // Traffic detail dialog
  const [trafficDetailOpen, setTrafficDetailOpen] = useState(false);
  const [selectedTraffic, setSelectedTraffic] = useState<TrafficEntry | null>(null);

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

  // Theme for animations
  const theme = useTheme();

  // Load proxies
  const loadProxies = useCallback(async () => {
    try {
      const data = await mitmClient.listProxies();
      setProxies(data);
    } catch (err: any) {
      console.error('Failed to load proxies:', err);
    }
  }, []);

  // Load traffic for selected proxy
  const loadTraffic = useCallback(async () => {
    if (!selectedProxy) return;
    try {
      const data = await mitmClient.getTraffic(selectedProxy);
      setTraffic(data.entries || []);
    } catch (err: any) {
      console.error('Failed to load traffic:', err);
    }
  }, [selectedProxy]);

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
      loadTraffic();
      loadRules();
      checkProxyHealth();
    }
  }, [selectedProxy, loadTraffic, loadRules]);

  // Auto-refresh traffic
  useEffect(() => {
    if (!autoRefresh || !selectedProxy) return;
    const interval = setInterval(loadTraffic, 2000);
    return () => clearInterval(interval);
  }, [autoRefresh, selectedProxy, loadTraffic]);

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
      setSuccess('Traffic cleared');
    } catch (err: any) {
      setError(err.message || 'Failed to clear traffic');
    }
  };

  // Add rule
  const handleAddRule = async () => {
    if (!selectedProxy) return;
    try {
      await mitmClient.addRule(selectedProxy, newRule);
      setSuccess('Rule added');
      setNewRuleOpen(false);
      setNewRule({
        name: '',
        enabled: true,
        match_direction: 'both',
        action: 'modify',
      });
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
  const exportTraffic = () => {
    const data = JSON.stringify(traffic, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mitm-traffic-${selectedProxy}-${new Date().toISOString()}.json`;
    a.click();
  };

  // Get selected proxy details
  const currentProxy = proxies.find(p => p.id === selectedProxy);

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
              </Tabs>

              {/* Tab panels */}
              <Box sx={{ flex: 1, overflow: 'auto' }}>
                {/* Traffic Log Tab */}
                <TabPanel value={tabValue} index={0}>
                  <Box sx={{ mb: 2, display: 'flex', gap: 1, alignItems: 'center' }}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={autoRefresh}
                          onChange={(e) => setAutoRefresh(e.target.checked)}
                        />
                      }
                      label="Auto Refresh"
                    />
                    <Button
                      size="small"
                      startIcon={<RefreshIcon />}
                      onClick={loadTraffic}
                    >
                      Refresh
                    </Button>
                    <Button
                      size="small"
                      startIcon={<ClearIcon />}
                      onClick={handleClearTraffic}
                    >
                      Clear
                    </Button>
                    <Button
                      size="small"
                      startIcon={<DownloadIcon />}
                      onClick={exportTraffic}
                      disabled={traffic.length === 0}
                    >
                      Export
                    </Button>
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
                        ) : (
                          traffic.map((entry) => (
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
                                <Typography variant="body2">{entry.duration_ms}ms</Typography>
                              </TableCell>
                              <TableCell>
                                {entry.modified && (
                                  <Chip label="Modified" size="small" color="warning" />
                                )}
                              </TableCell>
                              <TableCell>
                                <IconButton
                                  size="small"
                                  onClick={() => {
                                    setSelectedTraffic(entry);
                                    setTrafficDetailOpen(true);
                                  }}
                                >
                                  <ViewIcon />
                                </IconButton>
                              </TableCell>
                            </TableRow>
                          ))
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
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
                              {rule.match_host && <Chip label={`Host: ${rule.match_host}`} size="small" variant="outlined" />}
                              {rule.match_path && <Chip label={`Path: ${rule.match_path}`} size="small" variant="outlined" />}
                              {rule.match_method && <Chip label={`Method: ${rule.match_method}`} size="small" variant="outlined" />}
                              {rule.match_content_type && <Chip label={`Type: ${rule.match_content_type}`} size="small" variant="outlined" />}
                              {rule.delay_ms && rule.delay_ms > 0 && <Chip label={`Delay: ${rule.delay_ms}ms`} size="small" variant="outlined" />}
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
                  For header modifications, enter JSON in the format: {`{"Header-Name": "value"}`}
                </Alert>
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
                  
                  <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                    Headers
                  </Typography>
                  <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5 }}>
                    <pre style={{ margin: 0, fontSize: '12px', overflow: 'auto' }}>
                      {JSON.stringify(selectedTraffic.request.headers, null, 2)}
                    </pre>
                  </Box>

                  {selectedTraffic.request.body && (
                    <>
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                        Body
                      </Typography>
                      <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                        <pre style={{ margin: 0, fontSize: '12px' }}>
                          {selectedTraffic.request.body}
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
                      <Typography>{selectedTraffic.response.status_text}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        ({selectedTraffic.duration_ms}ms)
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

                    {selectedTraffic.response.body && (
                      <>
                        <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 2 }}>
                          Body
                        </Typography>
                        <Box sx={{ bgcolor: 'grey.900', p: 1, borderRadius: 1, mt: 0.5, maxHeight: 200, overflow: 'auto' }}>
                          <pre style={{ margin: 0, fontSize: '12px' }}>
                            {selectedTraffic.response.body}
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
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button
            startIcon={<CopyIcon />}
            onClick={() => copyToClipboard(JSON.stringify(selectedTraffic, null, 2))}
          >
            Copy JSON
          </Button>
          <Button onClick={() => setTrafficDetailOpen(false)}>Close</Button>
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
