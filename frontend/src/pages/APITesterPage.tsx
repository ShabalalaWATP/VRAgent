import React, { useState, useCallback, useEffect, useRef } from "react";
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Chip,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  IconButton,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
  InputAdornment,
  Stepper,
  Step,
  StepLabel,
  StepContent,
} from "@mui/material";
import {
  Api as ApiIcon,
  PlayArrow as PlayIcon,
  Security as SecurityIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  Send as SendIcon,
  CheckCircle as CheckIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Webhook as WebSocketIcon,
  Link as ProxyIcon,
  Timer as TimerIcon,
  Category as CategoryIcon,
  Info as InfoIcon,
  ContentCopy as CopyIcon,
  Refresh as RefreshIcon,
  Help as HelpIcon,
  Speed as SpeedIcon,
  Lock as LockIcon,
  VpnKey as KeyIcon,
  Code as CodeIcon,
  BugReport as BugIcon,
  Shield as ShieldIcon,
  ArrowBack as ArrowBackIcon,
  Analytics as AnalyticsIcon,
  Clear as ClearIcon,
  Radar as RadarIcon,
  SaveAlt as SaveIcon,
  FolderOpen as LoadIcon,
  Computer as VMIcon,
  NetworkCheck as NetworkIcon,
  Search as SearchIcon,
  Bookmarks as PresetIcon,
  School as LearnIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
  Token as TokenIcon,
  Description as SpecIcon,
  Chat as ChatIcon,
  Person as PersonIcon,
  SmartToy as SmartToyIcon,
  ExpandLess as ExpandLessIcon,
  AutoFixHigh as AutoTestIcon,
} from "@mui/icons-material";
import { useNavigate } from "react-router-dom";
import {
  apiTester,
  APITestRequest,
  APITestResult,
  APIEndpointConfig,
  APITestFinding,
  APIEndpointResult,
  APITestAIAnalysis,
  WebSocketTestRequest,
  WebSocketTestResult,
  OWASPAPITop10,
  NetworkDiscoveryRequest,
  NetworkDiscoveryResult,
  DiscoveredService,
  TargetPreset,
  BatchTestRequest,
  BatchTestResult,
  BatchTestTarget,
  OpenAPIParseResult,
  OpenAPIEndpoint,
  JWTAnalysisResult,
  APITesterChatMessage,
  AIAutoTestResult,
} from "../api/client";
import ReactMarkdown from "react-markdown";
import { useTheme, alpha } from "@mui/material/styles";

// Tab panel component
function TabPanel({ children, value, index, ...other }: any) {
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

// Severity color helper
const getSeverityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "info";
    case "info":
      return "default";
    default:
      return "default";
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical":
    case "high":
      return <ErrorIcon color="error" fontSize="small" />;
    case "medium":
      return <WarningIcon color="warning" fontSize="small" />;
    case "low":
      return <InfoIcon color="info" fontSize="small" />;
    default:
      return <InfoIcon color="disabled" fontSize="small" />;
  }
};

// HTTP Method colors
const getMethodColor = (method: string) => {
  switch (method?.toUpperCase()) {
    case "GET":
      return "#61affe";
    case "POST":
      return "#49cc90";
    case "PUT":
      return "#fca130";
    case "DELETE":
      return "#f93e3e";
    case "PATCH":
      return "#50e3c2";
    case "OPTIONS":
      return "#0d5aa7";
    case "HEAD":
      return "#9012fe";
    default:
      return "#999";
  }
};

export default function APITesterPage() {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState(0);
  
  // Request builder state
  const [baseUrl, setBaseUrl] = useState("");
  const [endpoints, setEndpoints] = useState<APIEndpointConfig[]>([
    { url: "", method: "GET" }
  ]);
  
  // Auth state
  const [authType, setAuthType] = useState<"none" | "basic" | "bearer" | "api_key">("none");
  const [authValue, setAuthValue] = useState("");
  
  // Test options
  const [testAuth, setTestAuth] = useState(true);
  const [testCors, setTestCors] = useState(true);
  const [testRateLimit, setTestRateLimit] = useState(true);
  const [testInputValidation, setTestInputValidation] = useState(true);
  const [testMethods, setTestMethods] = useState(true);
  const [testGraphQL, setTestGraphQL] = useState(false);
  
  // Results state
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<APITestResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<APITestAIAnalysis | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  
  // Quick scan state
  const [quickScanUrl, setQuickScanUrl] = useState("");
  
  // Proxy settings
  const [proxyUrl, setProxyUrl] = useState("");
  const [timeout, setTimeout] = useState(30);
  
  // WebSocket testing state
  const [wsUrl, setWsUrl] = useState("");
  const [wsAuthToken, setWsAuthToken] = useState("");
  const [wsMessages, setWsMessages] = useState<string[]>(["Hello", "Test message"]);
  const [wsLoading, setWsLoading] = useState(false);
  const [wsResult, setWsResult] = useState<WebSocketTestResult | null>(null);
  
  // OWASP API Top 10 reference
  const [owaspReference, setOwaspReference] = useState<OWASPAPITop10 | null>(null);
  const [owaspOpen, setOwaspOpen] = useState(false);
  
  // Payloads dialog
  const [payloadsOpen, setPayloadsOpen] = useState(false);
  const [payloads, setPayloads] = useState<Record<string, string[]>>({});
  
  // Headers reference dialog
  const [headersOpen, setHeadersOpen] = useState(false);
  const [headersInfo, setHeadersInfo] = useState<Record<string, { description: string; recommended: string }>>({});

  // Network Discovery state
  const [discoverySubnet, setDiscoverySubnet] = useState("192.168.1.0/24");
  const [discoveryPorts, setDiscoveryPorts] = useState("80,443,8080,3000,5000,8000");
  const [discoveryTimeout, setDiscoveryTimeout] = useState(1.5);
  const [discoveryMaxConcurrent, setDiscoveryMaxConcurrent] = useState(100);
  const [discoveryMaxHosts, setDiscoveryMaxHosts] = useState(256);
  const [discoveryOverallTimeout, setDiscoveryOverallTimeout] = useState(120);
  const [discoveryLoading, setDiscoveryLoading] = useState(false);
  const [discoveryResult, setDiscoveryResult] = useState<NetworkDiscoveryResult | null>(null);
  
  // Target Presets state
  const [presets, setPresets] = useState<TargetPreset[]>([]);
  const [presetsLoading, setPresetsLoading] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState<string>("");
  const [newPresetOpen, setNewPresetOpen] = useState(false);
  const [newPresetName, setNewPresetName] = useState("");
  const [newPresetDescription, setNewPresetDescription] = useState("");
  
  // Batch Testing state
  const [batchTargets, setBatchTargets] = useState<BatchTestTarget[]>([{ url: "" }]);
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResult, setBatchResult] = useState<BatchTestResult | null>(null);
  
  // Usage Guide state
  const [showGuide, setShowGuide] = useState(false);

  // OpenAPI Import state
  const [openApiContent, setOpenApiContent] = useState("");
  const [openApiUrl, setOpenApiUrl] = useState("");
  const [openApiLoading, setOpenApiLoading] = useState(false);
  const [openApiResult, setOpenApiResult] = useState<OpenAPIParseResult | null>(null);
  
  // JWT Analyzer state
  const [jwtToken, setJwtToken] = useState("");
  const [jwtTestSecrets, setJwtTestSecrets] = useState(true);
  const [jwtLoading, setJwtLoading] = useState(false);
  const [jwtResult, setJwtResult] = useState<JWTAnalysisResult | null>(null);
  
  // Export state
  const [exportLoading, setExportLoading] = useState(false);

  // AI Auto-Test state
  const [autoTestTarget, setAutoTestTarget] = useState("");
  const [autoTestPorts, setAutoTestPorts] = useState("");
  const [autoTestProbeEndpoints, setAutoTestProbeEndpoints] = useState(true);
  const [autoTestRunSecurity, setAutoTestRunSecurity] = useState(true);
  const [autoTestLoading, setAutoTestLoading] = useState(false);
  const [autoTestResult, setAutoTestResult] = useState<AIAutoTestResult | null>(null);
  const [autoTestNetworkTimeout, setAutoTestNetworkTimeout] = useState(1.0);
  const [autoTestMaxConcurrent, setAutoTestMaxConcurrent] = useState(200);
  
  // Detect if target is a network range
  const isNetworkTarget = /\/\d{1,2}$/.test(autoTestTarget.trim()) || 
                          /^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$/.test(autoTestTarget.trim());

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<APITesterChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const theme = useTheme();

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Load presets on mount
  useEffect(() => {
    loadPresets();
  }, []);

  // Handle sending chat message
  const handleSendChatMessage = async () => {
    const hasContext = result || batchResult || jwtResult || openApiResult || autoTestResult;
    if (!chatInput.trim() || !hasContext || chatLoading) return;

    const userMessage: APITesterChatMessage = { role: "user", content: chatInput.trim() };
    setChatMessages((prev) => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    setChatError(null);

    try {
      // Build test_result from autoTestResult if available
      const effectiveTestResult = result || (autoTestResult ? {
        base_url: autoTestResult.target,
        security_score: autoTestResult.security_score,
        total_findings: autoTestResult.total_findings,
        critical_count: autoTestResult.critical_count,
        high_count: autoTestResult.high_count,
        medium_count: autoTestResult.medium_count,
        low_count: autoTestResult.low_count,
        all_findings: autoTestResult.all_findings,
        endpoints_tested: autoTestResult.discovered_endpoints.length,
      } as any : undefined);

      const response = await apiTester.chatAboutTests({
        message: userMessage.content,
        conversation_history: chatMessages,
        context: {
          test_result: effectiveTestResult,
          batch_result: batchResult || undefined,
          jwt_result: jwtResult || undefined,
          openapi_result: openApiResult || undefined,
        },
      });

      if (response.error) {
        setChatError(response.error);
      } else {
        const assistantMessage: APITesterChatMessage = { role: "assistant", content: response.response };
        setChatMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle chat Enter key
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendChatMessage();
    }
  };

  // Handle AI Auto-Test
  const handleAutoTest = async () => {
    if (!autoTestTarget.trim()) {
      setError("Please enter an IP address, URL, or domain to test");
      return;
    }

    setAutoTestLoading(true);
    setAutoTestResult(null);
    setError(null);

    try {
      // Parse ports if provided
      const ports = autoTestPorts.trim()
        ? autoTestPorts.split(",").map(p => parseInt(p.trim())).filter(p => !isNaN(p))
        : undefined;

      const result = await apiTester.aiAutoTest({
        target: autoTestTarget.trim(),
        ports,
        probe_endpoints: autoTestProbeEndpoints,
        run_security_tests: autoTestRunSecurity,
        max_endpoints: 20,
        timeout: 15,
        network_timeout: autoTestNetworkTimeout,
        max_concurrent: autoTestMaxConcurrent,
      });

      setAutoTestResult(result);
      // Results now show inline in this tab
    } catch (err: any) {
      setError(err.message || "AI Auto-Test failed");
    } finally {
      setAutoTestLoading(false);
    }
  };

  // Load presets
  const loadPresets = async () => {
    setPresetsLoading(true);
    try {
      const data = await apiTester.getPresets();
      setPresets(data);
    } catch (err) {
      console.error("Failed to load presets", err);
    } finally {
      setPresetsLoading(false);
    }
  };

  // Apply preset
  const applyPreset = (presetId: string) => {
    const preset = presets.find(p => p.id === presetId);
    if (preset) {
      setBaseUrl(preset.base_url);
      if (preset.endpoints && preset.endpoints.length > 0) {
        setEndpoints(preset.endpoints.map(e => ({ url: e.path, method: e.method })));
      }
      if (preset.auth_type) {
        setAuthType(preset.auth_type as any);
        setAuthValue(preset.auth_value || "");
      }
      setSelectedPreset(presetId);
    }
  };

  // Save current config as preset
  const saveAsPreset = async () => {
    if (!newPresetName || !baseUrl) return;
    
    try {
      await apiTester.createPreset({
        name: newPresetName,
        description: newPresetDescription,
        base_url: baseUrl,
        endpoints: endpoints.filter(e => e.url).map(e => ({ method: e.method, path: e.url })),
        auth_type: authType !== "none" ? authType : undefined,
        auth_value: authType !== "none" ? authValue : undefined,
      });
      await loadPresets();
      setNewPresetOpen(false);
      setNewPresetName("");
      setNewPresetDescription("");
    } catch (err: any) {
      setError(err.message || "Failed to save preset");
    }
  };

  // Run network discovery
  const runDiscovery = async () => {
    setDiscoveryLoading(true);
    setError(null);
    setDiscoveryResult(null);

    try {
      const ports = discoveryPorts.split(",").map(p => parseInt(p.trim())).filter(p => !isNaN(p));
      const result = await apiTester.discoverServices({
        subnet: discoverySubnet,
        ports: ports.length > 0 ? ports : undefined,
        timeout: discoveryTimeout,
        max_concurrent: discoveryMaxConcurrent,
        max_hosts: discoveryMaxHosts,
        overall_timeout: discoveryOverallTimeout,
      });
      setDiscoveryResult(result);
    } catch (err: any) {
      setError(err.message || "Discovery failed");
    } finally {
      setDiscoveryLoading(false);
    }
  };

  // Add discovered service to batch targets
  const addDiscoveredToBatch = (service: DiscoveredService) => {
    setBatchTargets([...batchTargets, { url: service.url, name: `${service.ip}:${service.port}` }]);
  };

  // Run batch test
  const runBatchTest = async () => {
    const validTargets = batchTargets.filter(t => t.url);
    if (validTargets.length === 0) {
      setError("Please add at least one target");
      return;
    }

    setBatchLoading(true);
    setError(null);
    setBatchResult(null);

    try {
      const result = await apiTester.batchTest({
        targets: validTargets,
        test_options: {
          test_auth: testAuth,
          test_cors: testCors,
          test_input_validation: testInputValidation,
        },
        proxy_url: proxyUrl || undefined,
      });
      setBatchResult(result);
    } catch (err: any) {
      setError(err.message || "Batch test failed");
    } finally {
      setBatchLoading(false);
    }
  };

  // Import OpenAPI spec
  const importOpenAPI = async () => {
    if (!openApiContent && !openApiUrl) {
      setError("Please paste an OpenAPI spec or enter a URL");
      return;
    }

    setOpenApiLoading(true);
    setError(null);
    setOpenApiResult(null);

    try {
      const result = await apiTester.importOpenAPI({
        spec_content: openApiContent || undefined,
        spec_url: openApiUrl || undefined,
      });
      setOpenApiResult(result);
    } catch (err: any) {
      setError(err.message || "OpenAPI import failed");
    } finally {
      setOpenApiLoading(false);
    }
  };

  // Apply OpenAPI endpoints to test builder
  const applyOpenApiEndpoints = () => {
    if (!openApiResult) return;
    
    setBaseUrl(openApiResult.base_url || baseUrl);
    setEndpoints(openApiResult.endpoints.slice(0, 20).map(ep => ({
      url: ep.path,
      method: ep.method,
    })));
    setActiveTab(2); // Switch to Test Builder
  };

  // Analyze JWT token
  const analyzeJWT = async () => {
    if (!jwtToken.trim()) {
      setError("Please enter a JWT token");
      return;
    }

    setJwtLoading(true);
    setError(null);
    setJwtResult(null);

    try {
      const result = await apiTester.analyzeJWT({
        token: jwtToken.trim(),
        test_weak_secrets: jwtTestSecrets,
      });
      setJwtResult(result);
    } catch (err: any) {
      setError(err.message || "JWT analysis failed");
    } finally {
      setJwtLoading(false);
    }
  };

  // Export functions
  const exportResult = async (type: "test" | "batch" | "jwt" | "auto" | "websocket", format: "json" | "markdown" | "pdf" | "docx") => {
    setExportLoading(true);
    try {
      let content: Blob | string;
      let filename: string;
      const isBinary = format === "pdf" || format === "docx";
      const ext = format === "json" ? "json" : format === "markdown" ? "md" : format;
      
      if (type === "test" && result) {
        content = await apiTester.exportTestResult({
          test_result: result,
          format,
          title: "API Security Test Report",
        });
        filename = `api-test-report.${ext}`;
      } else if (type === "batch" && batchResult) {
        content = await apiTester.exportBatchResult({
          batch_result: batchResult,
          format,
          title: "Batch API Test Report",
        });
        filename = `batch-test-report.${ext}`;
      } else if (type === "jwt" && jwtResult) {
        content = await apiTester.exportJWTResult({
          jwt_result: jwtResult,
          format,
        });
        filename = `jwt-analysis.${ext}`;
      } else if (type === "auto" && autoTestResult) {
        content = await apiTester.exportAutoTestResult({
          auto_test_result: autoTestResult,
          format,
          title: "AI Auto-Test Security Report",
        });
        filename = `auto-test-report.${ext}`;
      } else if (type === "websocket" && wsResult) {
        content = await apiTester.exportWebSocketResult({
          websocket_result: wsResult,
          format,
          title: "WebSocket Security Test Report",
        });
        filename = `websocket-test-report.${ext}`;
      } else {
        return;
      }

      // Download the file
      let blob: Blob;
      if (isBinary && content instanceof Blob) {
        blob = content;
      } else {
        const mimeType = format === "json" ? "application/json" 
          : format === "pdf" ? "application/pdf"
          : format === "docx" ? "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
          : "text/markdown";
        blob = new Blob([content as string], { type: mimeType });
      }
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || "Export failed");
    } finally {
      setExportLoading(false);
    }
  };

  // Add batch target
  const addBatchTarget = () => {
    setBatchTargets([...batchTargets, { url: "" }]);
  };

  // Remove batch target
  const removeBatchTarget = (index: number) => {
    setBatchTargets(batchTargets.filter((_, i) => i !== index));
  };

  // Update batch target
  const updateBatchTarget = (index: number, field: keyof BatchTestTarget, value: string) => {
    const newTargets = [...batchTargets];
    newTargets[index] = { ...newTargets[index], [field]: value };
    setBatchTargets(newTargets);
  };

  // Add endpoint
  const addEndpoint = () => {
    setEndpoints([...endpoints, { url: "", method: "GET" }]);
  };

  // Remove endpoint
  const removeEndpoint = (index: number) => {
    setEndpoints(endpoints.filter((_, i) => i !== index));
  };

  // Update endpoint
  const updateEndpoint = (index: number, field: keyof APIEndpointConfig, value: any) => {
    const newEndpoints = [...endpoints];
    newEndpoints[index] = { ...newEndpoints[index], [field]: value };
    setEndpoints(newEndpoints);
  };

  // Run full test
  const runTest = async () => {
    if (!baseUrl) {
      setError("Please enter a base URL");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setAiAnalysis(null);

    try {
      const request: APITestRequest = {
        base_url: baseUrl,
        endpoints: endpoints.filter(e => e.url),
        auth_type: authType !== "none" ? authType : undefined,
        auth_value: authType !== "none" ? authValue : undefined,
        test_auth: testAuth,
        test_cors: testCors,
        test_rate_limit: testRateLimit,
        test_input_validation: testInputValidation,
        test_methods: testMethods,
        test_graphql: testGraphQL,
        proxy_url: proxyUrl || undefined,
        timeout: timeout,
      };

      const testResult = await apiTester.testAPI(request);
      setResult(testResult);
      // Results now show inline in this tab
    } catch (err: any) {
      setError(err.message || "Test failed");
    } finally {
      setLoading(false);
    }
  };

  // Run quick scan
  const runQuickScan = async () => {
    if (!quickScanUrl) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setAiAnalysis(null);

    try {
      const testResult = await apiTester.quickScan({ 
        url: quickScanUrl,
        proxy_url: proxyUrl || undefined,
      });
      setResult(testResult);
      // Results now show inline in this tab
    } catch (err: any) {
      setError(err.message || "Quick scan failed");
    } finally {
      setLoading(false);
    }
  };

  // Get AI analysis
  const getAIAnalysis = async () => {
    if (!result) return;

    setAiLoading(true);
    try {
      const analysis = await apiTester.analyzeResults(result);
      setAiAnalysis(analysis);
    } catch (err: any) {
      setError(err.message || "AI analysis failed");
    } finally {
      setAiLoading(false);
    }
  };

  // Load payloads
  const loadPayloads = async () => {
    try {
      const data = await apiTester.getPayloads();
      setPayloads(data);
      setPayloadsOpen(true);
    } catch (err) {
      console.error("Failed to load payloads", err);
    }
  };

  // Load headers info
  const loadHeadersInfo = async () => {
    try {
      const data = await apiTester.getSecurityHeadersInfo();
      setHeadersInfo(data);
      setHeadersOpen(true);
    } catch (err) {
      console.error("Failed to load headers info", err);
    }
  };

  // Run WebSocket test
  const runWebSocketTest = async () => {
    if (!wsUrl) {
      setError("Please enter a WebSocket URL");
      return;
    }

    setWsLoading(true);
    setError(null);
    setWsResult(null);

    try {
      const request: WebSocketTestRequest = {
        url: wsUrl,
        auth_token: wsAuthToken || undefined,
        test_messages: wsMessages.filter(m => m.trim()),
      };
      const result = await apiTester.testWebSocket(request);
      setWsResult(result);
    } catch (err: any) {
      setError(err.message || "WebSocket test failed");
    } finally {
      setWsLoading(false);
    }
  };

  // Add WS test message
  const addWsMessage = () => {
    setWsMessages([...wsMessages, ""]);
  };

  // Remove WS test message
  const removeWsMessage = (index: number) => {
    setWsMessages(wsMessages.filter((_, i) => i !== index));
  };

  // Update WS message
  const updateWsMessage = (index: number, value: string) => {
    const newMessages = [...wsMessages];
    newMessages[index] = value;
    setWsMessages(newMessages);
  };

  // Load OWASP API Top 10 reference
  const loadOwaspReference = async () => {
    try {
      const data = await apiTester.getOWASPAPITop10();
      setOwaspReference(data);
      setOwaspOpen(true);
    } catch (err) {
      console.error("Failed to load OWASP reference", err);
    }
  };

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Clear results
  const clearResults = () => {
    setResult(null);
    setAiAnalysis(null);
    setError(null);
  };

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate("/network")} color="primary">
          <ArrowBackIcon />
        </IconButton>
        <ApiIcon sx={{ fontSize: 40, color: "primary.main" }} />
        <Box>
          <Typography variant="h4">API Endpoint Tester</Typography>
          <Typography variant="body2" color="text.secondary">
            Comprehensive API security testing - authentication, CORS, input validation, and more
          </Typography>
        </Box>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          variant={showGuide ? "contained" : "outlined"}
          color="info"
          startIcon={<LearnIcon />}
          onClick={() => setShowGuide(!showGuide)}
        >
          {showGuide ? "Hide Guide" : "Usage Guide"}
        </Button>
        <Button
          variant="outlined"
          startIcon={<HelpIcon />}
          onClick={loadHeadersInfo}
        >
          Security Headers
        </Button>
        <Button
          variant="outlined"
          startIcon={<BugIcon />}
          onClick={loadPayloads}
        >
          Test Payloads
        </Button>
      </Box>

      {/* Usage Guide Panel */}
      <Collapse in={showGuide}>
        <Paper sx={{ p: 3, mb: 3, bgcolor: "info.dark", color: "white" }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LearnIcon />
            How to Use the API Endpoint Tester
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                🚀 Quick Start
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="1. Quick Scan" 
                    secondary="Enter any API URL and click 'Quick Scan' for instant security analysis"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="2. Full Test" 
                    secondary="Enter a base URL, add multiple endpoints, configure auth, and run comprehensive tests"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="3. WebSocket" 
                    secondary="Test WebSocket endpoints for XSS, auth bypass, and other vulnerabilities"
                  />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                🔧 Air-Gapped / VM Network Features
              </Typography>
              <List dense>
                <ListItem>
                  <ListItemText 
                    primary="Network Discovery" 
                    secondary="Scan subnets to find HTTP/API services on VMs (e.g., 192.168.1.0/24)"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Target Presets" 
                    secondary="Save frequently used targets for quick access. Great for lab VMs!"
                  />
                </ListItem>
                <ListItem>
                  <ListItemText 
                    primary="Batch Testing" 
                    secondary="Test multiple VMs/endpoints at once and compare security scores"
                  />
                </ListItem>
              </List>
            </Grid>
            <Grid item xs={12}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>
                🛡️ Security Tests Performed
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {["SQL Injection", "XSS Reflection", "CORS Misconfiguration", "Auth Bypass", "Rate Limiting", 
                  "Path Traversal", "Security Headers", "HTTP Methods", "Error Disclosure", "GraphQL Introspection"].map(test => (
                  <Chip key={test} label={test} size="small" sx={{ bgcolor: "rgba(255,255,255,0.2)" }} />
                ))}
              </Box>
            </Grid>
            <Grid item xs={12}>
              <Alert severity="info" sx={{ bgcolor: "rgba(255,255,255,0.1)" }}>
                <Typography variant="body2">
                  <strong>Proxy Support:</strong> Configure a proxy URL (e.g., http://127.0.0.1:8080) to route all requests through Burp Suite or ZAP for detailed traffic analysis.
                </Typography>
              </Alert>
            </Grid>
          </Grid>
          <Box sx={{ mt: 2, display: "flex", gap: 2 }}>
            <Button 
              variant="outlined" 
              sx={{ color: "white", borderColor: "white" }}
              onClick={() => navigate("/learn/api-testing")}
              startIcon={<LearnIcon />}
            >
              Full Tutorial in Learn Hub
            </Button>
          </Box>
        </Paper>
      </Collapse>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Main Tabs - Logical workflow order */}
      <Tabs 
        value={activeTab} 
        onChange={(_, v) => setActiveTab(v)} 
        sx={{ 
          mb: 2,
          '& .MuiTabs-flexContainer': {
            justifyContent: 'center',
            flexWrap: 'wrap',
          },
        }} 
        variant="scrollable" 
        scrollButtons="auto"
      >
        {/* Discovery & Auto-Testing */}
        <Tab icon={<AutoTestIcon />} label={`AI Auto-Test ${autoTestResult ? `(${autoTestResult.total_findings})` : ""}`} />
        <Tab icon={<RadarIcon />} label="Network Discovery" />
        
        {/* Manual Testing Tools */}
        <Tab icon={<SendIcon />} label={`Test Builder ${result ? `(${result.total_findings})` : ""}`} />
        <Tab icon={<SpecIcon />} label={`OpenAPI Import ${openApiResult ? `(${openApiResult.endpoints.length})` : ""}`} />
        <Tab icon={<VMIcon />} label={`Batch Testing ${batchResult ? `(${batchResult.total_findings})` : ""}`} />
        
        {/* Specialized Testing */}
        <Tab icon={<WebSocketIcon />} label={`WebSocket ${wsResult ? `(${wsResult.findings.length})` : ""}`} />
        <Tab icon={<TokenIcon />} label={`JWT Analyzer ${jwtResult ? "(✓)" : ""}`} />
      </Tabs>

      {/* Tab 0: AI Auto-Test */}
      <TabPanel value={activeTab} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                  <AutoTestIcon color="primary" />
                  <Typography variant="h6">AI-Powered Automated Security Testing</Typography>
                </Box>
                
                <Alert severity="info" sx={{ mb: 3 }}>
                  <Typography variant="body2">
                    <strong>Just enter an IP address, URL, domain, or network range.</strong> The AI will automatically:
                  </Typography>
                  <ul style={{ margin: "8px 0", paddingLeft: 20 }}>
                    <li>Detect and scan common web service ports</li>
                    <li>Discover API endpoints and documentation</li>
                    <li>Run comprehensive security tests</li>
                    <li>Generate a detailed vulnerability report</li>
                  </ul>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    <strong>Network scans:</strong> Supports CIDR notation (192.168.1.0/24) and IP ranges (192.168.1.1-192.168.1.254).
                    A /24 network (256 hosts) typically scans in under 30 seconds.
                  </Typography>
                </Alert>

                {isNetworkTarget && (
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    <Typography variant="body2">
                      <strong>🌐 Network Scan Detected:</strong> Scanning {autoTestTarget.trim()} with {autoTestMaxConcurrent} concurrent connections.
                      {autoTestTarget.includes("/24") && " (up to 256 hosts)"}
                      {autoTestTarget.includes("/16") && " (limited to 256 hosts for safety)"}
                    </Typography>
                  </Alert>
                )}

                <Grid container spacing={2}>
                  <Grid item xs={12} md={8}>
                    <TextField
                      fullWidth
                      label="Target (IP, URL, Domain, or Network Range)"
                      value={autoTestTarget}
                      onChange={(e) => setAutoTestTarget(e.target.value)}
                      placeholder="192.168.1.100, 192.168.1.0/24, or http://api.example.com"
                      helperText="Examples: 192.168.1.1, 192.168.1.0/24 (network scan), 10.0.0.1-10.0.0.50 (range), api.example.com"
                    />
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <TextField
                      fullWidth
                      label="Custom Ports (optional)"
                      value={autoTestPorts}
                      onChange={(e) => setAutoTestPorts(e.target.value)}
                      placeholder="80, 443, 8080, 3000"
                      helperText="Leave empty to scan common ports"
                    />
                  </Grid>
                  
                  {/* Network scan settings - show when CIDR/range detected */}
                  {isNetworkTarget && (
                    <>
                      <Grid item xs={6} md={3}>
                        <TextField
                          fullWidth
                          type="number"
                          label="Network Timeout (s)"
                          value={autoTestNetworkTimeout}
                          onChange={(e) => setAutoTestNetworkTimeout(parseFloat(e.target.value) || 1.0)}
                          inputProps={{ min: 0.5, max: 10, step: 0.5 }}
                          helperText="Lower = faster (may miss slow hosts)"
                        />
                      </Grid>
                      <Grid item xs={6} md={3}>
                        <TextField
                          fullWidth
                          type="number"
                          label="Max Concurrent"
                          value={autoTestMaxConcurrent}
                          onChange={(e) => setAutoTestMaxConcurrent(parseInt(e.target.value) || 200)}
                          inputProps={{ min: 50, max: 500, step: 50 }}
                          helperText="Higher = faster"
                        />
                      </Grid>
                    </>
                  )}
                  
                  <Grid item xs={12}>
                    <Box sx={{ display: "flex", gap: 3, flexWrap: "wrap" }}>
                      <FormControlLabel
                        control={
                          <Switch
                            checked={autoTestProbeEndpoints}
                            onChange={(e) => setAutoTestProbeEndpoints(e.target.checked)}
                          />
                        }
                        label="Discover API Endpoints"
                      />
                      <FormControlLabel
                        control={
                          <Switch
                            checked={autoTestRunSecurity}
                            onChange={(e) => setAutoTestRunSecurity(e.target.checked)}
                          />
                        }
                        label="Run Security Tests"
                      />
                    </Box>
                  </Grid>
                  <Grid item xs={12}>
                    <Button
                      variant="contained"
                      size="large"
                      onClick={handleAutoTest}
                      disabled={autoTestLoading || !autoTestTarget.trim()}
                      startIcon={autoTestLoading ? <CircularProgress size={20} /> : <AutoTestIcon />}
                      sx={{ minWidth: 200 }}
                    >
                      {autoTestLoading 
                        ? (isNetworkTarget ? "Scanning Network..." : "Scanning...") 
                        : (isNetworkTarget ? "Start Network Scan" : "Start AI Auto-Test")}
                    </Button>
                  </Grid>
                </Grid>
              </CardContent>
            </Card>
          </Grid>

          {/* Auto-Test Results Preview */}
          {autoTestResult && (
            <Grid item xs={12}>
              <Card>
                <CardContent>
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2, flexWrap: "wrap", gap: 1 }}>
                    <Typography variant="h6">
                      Scan Results: {autoTestResult.target}
                    </Typography>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                      <Chip
                        label={`Score: ${autoTestResult.security_score}/100`}
                        color={autoTestResult.security_score >= 80 ? "success" : autoTestResult.security_score >= 60 ? "warning" : "error"}
                      />
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportResult("auto", "json")}
                        disabled={exportLoading}
                      >
                        JSON
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportResult("auto", "markdown")}
                        disabled={exportLoading}
                      >
                        MD
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        color="primary"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportResult("auto", "pdf")}
                        disabled={exportLoading}
                      >
                        PDF
                      </Button>
                      <Button
                        size="small"
                        variant="outlined"
                        color="secondary"
                        startIcon={<DownloadIcon />}
                        onClick={() => exportResult("auto", "docx")}
                        disabled={exportLoading}
                      >
                        Word
                      </Button>
                    </Box>
                  </Box>

                  <Grid container spacing={2} sx={{ mb: 2 }}>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "error.main", color: "white" }}>
                        <Typography variant="h4">{autoTestResult.critical_count}</Typography>
                        <Typography variant="caption">Critical</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "warning.main", color: "white" }}>
                        <Typography variant="h4">{autoTestResult.high_count}</Typography>
                        <Typography variant="caption">High</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "warning.light" }}>
                        <Typography variant="h4">{autoTestResult.medium_count}</Typography>
                        <Typography variant="caption">Medium</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "info.main", color: "white" }}>
                        <Typography variant="h4">{autoTestResult.low_count}</Typography>
                        <Typography variant="caption">Low</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "grey.300" }}>
                        <Typography variant="h4">{autoTestResult.discovered_endpoints.length}</Typography>
                        <Typography variant="caption">Endpoints</Typography>
                      </Paper>
                    </Grid>
                    <Grid item xs={6} md={2}>
                      <Paper sx={{ p: 2, textAlign: "center", bgcolor: "grey.200" }}>
                        <Typography variant="h4">{autoTestResult.scan_duration_seconds.toFixed(1)}s</Typography>
                        <Typography variant="caption">Duration</Typography>
                      </Paper>
                    </Grid>
                  </Grid>

                  {/* Discovered Services */}
                  {autoTestResult.discovered_services.length > 0 && (
                    <Accordion defaultExpanded>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          Discovered Services ({autoTestResult.discovered_services.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <TableContainer>
                          <Table size="small">
                            <TableHead>
                              <TableRow>
                                <TableCell>Port</TableCell>
                                <TableCell>Protocol</TableCell>
                                <TableCell>URL</TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell>Server</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {autoTestResult.discovered_services.map((svc, i) => (
                                <TableRow key={i}>
                                  <TableCell><Chip label={svc.port} size="small" /></TableCell>
                                  <TableCell>{svc.scheme.toUpperCase()}</TableCell>
                                  <TableCell><code>{svc.url}</code></TableCell>
                                  <TableCell>{svc.status_code}</TableCell>
                                  <TableCell>{svc.server || "Unknown"}</TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* Discovered Endpoints */}
                  {autoTestResult.discovered_endpoints.length > 0 && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          Discovered Endpoints ({autoTestResult.discovered_endpoints.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <TableContainer sx={{ maxHeight: 300 }}>
                          <Table size="small" stickyHeader>
                            <TableHead>
                              <TableRow>
                                <TableCell>Path</TableCell>
                                <TableCell>Status</TableCell>
                                <TableCell>Type</TableCell>
                                <TableCell>Auth</TableCell>
                              </TableRow>
                            </TableHead>
                            <TableBody>
                              {autoTestResult.discovered_endpoints.map((ep, i) => (
                                <TableRow key={i}>
                                  <TableCell><code>{ep.path}</code></TableCell>
                                  <TableCell>{ep.status_code}</TableCell>
                                  <TableCell>
                                    {ep.is_json && <Chip label="JSON" size="small" color="primary" sx={{ mr: 0.5 }} />}
                                    {ep.is_html && <Chip label="HTML" size="small" color="secondary" />}
                                  </TableCell>
                                  <TableCell>
                                    {ep.requires_auth && <Chip label="Auth Required" size="small" color="warning" />}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </TableContainer>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  {/* AI Summary - Always show */}
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">🤖 AI Security Report</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Paper sx={{ p: 2, bgcolor: "background.default" }}>
                        {autoTestResult.ai_summary ? (
                          <ReactMarkdown>{autoTestResult.ai_summary}</ReactMarkdown>
                        ) : (
                          <Typography color="text.secondary">
                            No AI summary generated. This may happen if the scan encountered errors.
                            {autoTestResult.error && (
                              <Box component="span" sx={{ display: "block", mt: 1, color: "error.main" }}>
                                Error: {autoTestResult.error}
                              </Box>
                            )}
                          </Typography>
                        )}
                      </Paper>
                    </AccordionDetails>
                  </Accordion>

                  {/* Security Findings - Full list */}
                  {autoTestResult.all_findings.length > 0 && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">
                          🔍 All Security Findings ({autoTestResult.all_findings.length})
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box sx={{ maxHeight: 500, overflow: "auto" }}>
                          {autoTestResult.all_findings
                            .sort((a, b) => {
                              const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                              return (order[a.severity?.toLowerCase() as keyof typeof order] || 5) - 
                                     (order[b.severity?.toLowerCase() as keyof typeof order] || 5);
                            })
                            .map((finding, index) => {
                              const severity = finding.severity?.toLowerCase() || "info";
                              const colorMap: Record<string, string> = {
                                critical: "#d32f2f",
                                high: "#f44336",
                                medium: "#ff9800",
                                low: "#2196f3",
                                info: "#9e9e9e",
                              };
                              return (
                                <Card key={index} sx={{ mb: 1, borderLeft: `4px solid ${colorMap[severity]}` }}>
                                  <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
                                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                      <Chip
                                        label={severity.toUpperCase()}
                                        size="small"
                                        sx={{ bgcolor: colorMap[severity], color: "white", fontWeight: "bold" }}
                                      />
                                      <Typography variant="subtitle2" fontWeight="bold">
                                        {finding.title}
                                      </Typography>
                                    </Box>
                                    {finding.endpoint && (
                                      <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                                        <strong>Endpoint:</strong> <code>{finding.endpoint}</code>
                                      </Typography>
                                    )}
                                    {finding.description && (
                                      <Typography variant="body2" sx={{ mb: 0.5 }}>
                                        {finding.description}
                                      </Typography>
                                    )}
                                    {finding.remediation && (
                                      <Alert severity="info" sx={{ mt: 1, py: 0 }}>
                                        <Typography variant="body2">
                                          <strong>Fix:</strong> {finding.remediation}
                                        </Typography>
                                      </Alert>
                                    )}
                                    <Box sx={{ mt: 1, display: "flex", gap: 1, flexWrap: "wrap" }}>
                                      {finding.cwe && <Chip label={finding.cwe} size="small" variant="outlined" />}
                                      {finding.owasp_api && <Chip label={finding.owasp_api} size="small" variant="outlined" color="primary" />}
                                      {finding.category && <Chip label={finding.category} size="small" variant="outlined" color="secondary" />}
                                    </Box>
                                  </CardContent>
                                </Card>
                              );
                            })}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  )}

                </CardContent>
              </Card>
            </Grid>
          )}
        </Grid>
      </TabPanel>

      {/* Tab 2: Test Builder */}
      <TabPanel value={activeTab} index={2}>
        <Grid container spacing={3}>
          {/* Target Presets Bar */}
          <Grid item xs={12}>
            <Paper sx={{ p: 2, display: "flex", alignItems: "center", gap: 2, flexWrap: "wrap" }}>
              <PresetIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">Target Presets:</Typography>
              <FormControl size="small" sx={{ minWidth: 200 }}>
                <Select
                  value={selectedPreset}
                  displayEmpty
                  onChange={(e) => applyPreset(e.target.value)}
                >
                  <MenuItem value="">
                    <em>Select a preset...</em>
                  </MenuItem>
                  {presets.map((preset) => (
                    <MenuItem key={preset.id} value={preset.id}>
                      {preset.name} {preset.is_default && <Chip label="Default" size="small" sx={{ ml: 1 }} />}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              <IconButton onClick={loadPresets} disabled={presetsLoading} size="small">
                <RefreshIcon />
              </IconButton>
              <Box sx={{ flexGrow: 1 }} />
              <Button
                variant="outlined"
                size="small"
                startIcon={<SaveIcon />}
                onClick={() => setNewPresetOpen(true)}
                disabled={!baseUrl}
              >
                Save as Preset
              </Button>
            </Paper>
          </Grid>

          {/* Quick Scan Card */}
          <Grid item xs={12}>
            <Card sx={{ bgcolor: "background.paper", mb: 2 }}>
              <CardContent>
                <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <SpeedIcon color="primary" />
                  Quick Scan
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Fast security scan of a single endpoint
                </Typography>
                <Box sx={{ display: "flex", gap: 2 }}>
                  <TextField
                    fullWidth
                    label="URL"
                    placeholder="https://api.example.com/v1/users"
                    value={quickScanUrl}
                    onChange={(e) => setQuickScanUrl(e.target.value)}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <ApiIcon color="action" />
                        </InputAdornment>
                      ),
                    }}
                  />
                  <Button
                    variant="contained"
                    onClick={runQuickScan}
                    disabled={loading || !quickScanUrl}
                    startIcon={loading ? <CircularProgress size={20} /> : <PlayIcon />}
                    sx={{ minWidth: 150 }}
                  >
                    Quick Scan
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>

          {/* Full Test Configuration */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <CodeIcon color="primary" />
                Request Builder
              </Typography>

              {/* Base URL */}
              <TextField
                fullWidth
                label="Base URL"
                placeholder="https://api.example.com"
                value={baseUrl}
                onChange={(e) => setBaseUrl(e.target.value)}
                sx={{ mb: 3 }}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <ApiIcon color="action" />
                    </InputAdornment>
                  ),
                }}
              />

              {/* Endpoints */}
              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                  <Typography variant="subtitle1">Endpoints to Test</Typography>
                  <Button startIcon={<AddIcon />} onClick={addEndpoint} size="small">
                    Add Endpoint
                  </Button>
                </Box>
                
                {endpoints.map((endpoint, index) => (
                  <Box key={index} sx={{ display: "flex", gap: 1, mb: 2 }}>
                    <FormControl size="small" sx={{ minWidth: 120 }}>
                      <Select
                        value={endpoint.method}
                        onChange={(e) => updateEndpoint(index, "method", e.target.value)}
                        sx={{
                          "& .MuiSelect-select": {
                            fontWeight: "bold",
                            color: getMethodColor(endpoint.method),
                          },
                        }}
                      >
                        {["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"].map((m) => (
                          <MenuItem key={m} value={m} sx={{ fontWeight: "bold", color: getMethodColor(m) }}>
                            {m}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                    <TextField
                      fullWidth
                      size="small"
                      placeholder="/api/v1/endpoint"
                      value={endpoint.url}
                      onChange={(e) => updateEndpoint(index, "url", e.target.value)}
                    />
                    {endpoints.length > 1 && (
                      <IconButton onClick={() => removeEndpoint(index)} color="error" size="small">
                        <DeleteIcon />
                      </IconButton>
                    )}
                  </Box>
                ))}
              </Box>

              <Divider sx={{ my: 2 }} />

              {/* Authentication */}
              <Typography variant="subtitle1" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <LockIcon fontSize="small" />
                Authentication
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={4}>
                  <FormControl fullWidth size="small">
                    <InputLabel>Auth Type</InputLabel>
                    <Select
                      value={authType}
                      label="Auth Type"
                      onChange={(e) => setAuthType(e.target.value as any)}
                    >
                      <MenuItem value="none">None</MenuItem>
                      <MenuItem value="bearer">Bearer Token</MenuItem>
                      <MenuItem value="basic">Basic Auth</MenuItem>
                      <MenuItem value="api_key">API Key</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} sm={8}>
                  {authType !== "none" && (
                    <TextField
                      fullWidth
                      size="small"
                      label={
                        authType === "bearer"
                          ? "Bearer Token"
                          : authType === "basic"
                          ? "Base64 Credentials"
                          : "API Key"
                      }
                      placeholder={
                        authType === "bearer"
                          ? "eyJhbGciOiJIUzI1NiIsInR..."
                          : authType === "basic"
                          ? "dXNlcjpwYXNzd29yZA=="
                          : "your-api-key"
                      }
                      value={authValue}
                      onChange={(e) => setAuthValue(e.target.value)}
                      type="password"
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <KeyIcon color="action" />
                          </InputAdornment>
                        ),
                      }}
                    />
                  )}
                </Grid>
              </Grid>

              <Divider sx={{ my: 2 }} />

              {/* Proxy Settings */}
              <Typography variant="subtitle1" sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                <ProxyIcon fontSize="small" />
                Proxy Settings (Optional)
              </Typography>

              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={12} sm={8}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Proxy URL"
                    placeholder="http://127.0.0.1:8080"
                    value={proxyUrl}
                    onChange={(e) => setProxyUrl(e.target.value)}
                    helperText="Use for traffic interception (e.g., Burp Suite, ZAP)"
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <ProxyIcon color="action" />
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>
                <Grid item xs={12} sm={4}>
                  <TextField
                    fullWidth
                    size="small"
                    type="number"
                    label="Timeout (seconds)"
                    value={timeout}
                    onChange={(e) => setTimeout(Number(e.target.value))}
                    InputProps={{
                      startAdornment: (
                        <InputAdornment position="start">
                          <TimerIcon color="action" />
                        </InputAdornment>
                      ),
                    }}
                  />
                </Grid>
              </Grid>

              {/* Run Test Button */}
              <Button
                variant="contained"
                size="large"
                fullWidth
                onClick={runTest}
                disabled={loading || !baseUrl}
                startIcon={loading ? <CircularProgress size={20} /> : <PlayIcon />}
              >
                {loading ? "Running Security Tests..." : "Run Security Tests"}
              </Button>
            </Paper>
          </Grid>

          {/* Test Options */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <SecurityIcon color="primary" />
                Security Tests
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Select which security tests to run
              </Typography>

              <List dense>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testAuth} onChange={(e) => setTestAuth(e.target.checked)} />}
                    label="Authentication Testing"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testCors} onChange={(e) => setTestCors(e.target.checked)} />}
                    label="CORS Configuration"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testRateLimit} onChange={(e) => setTestRateLimit(e.target.checked)} />}
                    label="Rate Limiting"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testInputValidation} onChange={(e) => setTestInputValidation(e.target.checked)} />}
                    label="Input Validation (SQLi/XSS)"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testMethods} onChange={(e) => setTestMethods(e.target.checked)} />}
                    label="HTTP Method Enumeration"
                  />
                </ListItem>
                <ListItem>
                  <FormControlLabel
                    control={<Switch checked={testGraphQL} onChange={(e) => setTestGraphQL(e.target.checked)} />}
                    label="GraphQL Testing"
                  />
                </ListItem>
              </List>

              <Divider sx={{ my: 2 }} />

              {/* What we test */}
              <Typography variant="subtitle2" gutterBottom>
                Tests Include:
              </Typography>
              <List dense>
                {[
                  "Security headers analysis",
                  "CORS misconfiguration",
                  "Authentication bypass",
                  "Rate limit detection",
                  "SQL injection patterns",
                  "XSS reflection",
                  "Path traversal",
                  "Error disclosure",
                  "Sensitive data exposure",
                  "HTTP verb tampering",
                  "GraphQL introspection",
                ].map((item, i) => (
                  <ListItem key={i} sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      <CheckIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText 
                      primary={item} 
                      primaryTypographyProps={{ variant: "body2" }} 
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Payloads Dialog */}
      <Dialog open={payloadsOpen} onClose={() => setPayloadsOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Security Test Payloads</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Common payloads used for security testing. Use these for manual testing.
          </Typography>
          {Object.entries(payloads).map(([category, items]) => (
            <Accordion key={category}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ textTransform: "capitalize" }}>
                  {category.replace(/_/g, " ")} ({items.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {items.map((payload, i) => (
                    <ListItem
                      key={i}
                      secondaryAction={
                        <IconButton edge="end" onClick={() => copyToClipboard(payload)} size="small">
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      }
                    >
                      <ListItemText
                        primary={
                          <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                            {payload}
                          </Typography>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPayloadsOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Headers Info Dialog */}
      <Dialog open={headersOpen} onClose={() => setHeadersOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Security Headers Reference</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Recommended security headers for API endpoints.
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Header</TableCell>
                  <TableCell>Description</TableCell>
                  <TableCell>Recommended Value</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.entries(headersInfo).map(([header, info]) => (
                  <TableRow key={header}>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: "monospace", fontWeight: "bold" }}>
                        {header}
                      </Typography>
                    </TableCell>
                    <TableCell>{info.description}</TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                        {info.recommended}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHeadersOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* AI Chat Panel */}
      {(result || batchResult || jwtResult || openApiResult || autoTestResult) && (
        <Paper
          elevation={3}
          sx={{
            position: "fixed",
            bottom: 0,
            left: { xs: 0, md: 240 },
            right: 0,
            zIndex: 1200,
            borderTopLeftRadius: 12,
            borderTopRightRadius: 12,
            overflow: "hidden",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => setChatOpen(!chatOpen)}
            sx={{
              p: 2,
              bgcolor: theme.palette.primary.main,
              color: "white",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { bgcolor: theme.palette.primary.dark },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask AI About Your API Security Tests
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
                maxHeight: 400,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "text.disabled", mb: 1 }} />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ask me anything about your API security test results!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1, alignItems: "center" }}>
                    {[
                      "What are the most critical vulnerabilities?",
                      "How can I fix the authentication issues?",
                      "Explain the OWASP categories in my findings",
                      "Summarize the security posture of my API",
                      "What should I prioritize fixing first?",
                    ].map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => {
                          setChatInput(suggestion);
                        }}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat Messages */}
              {chatMessages.map((msg, i) => (
                <Box
                  key={i}
                  sx={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      maxWidth: "85%",
                      display: "flex",
                      gap: 1,
                      flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {msg.role === "user" ? (
                        <PersonIcon sx={{ fontSize: 18, color: "white" }} />
                      ) : (
                        <SmartToyIcon sx={{ fontSize: 18, color: "white" }} />
                      )}
                    </Box>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& code": {
                          bgcolor: alpha(msg.role === "user" ? "#fff" : theme.palette.primary.main, 0.2),
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
                        bgcolor: theme.palette.secondary.main,
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
                  placeholder="Ask a question about your API security tests..."
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
                  onClick={handleSendChatMessage}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: theme.palette.primary.main,
                    color: "white",
                    "&:hover": { bgcolor: theme.palette.primary.dark },
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

      {/* OWASP API Top 10 Reference Dialog */}
      <Dialog open={owaspOpen} onClose={() => setOwaspOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CategoryIcon color="primary" />
          OWASP API Security Top 10 ({owaspReference?.version || "2023"})
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            The OWASP API Security Top 10 represents the most critical security risks to APIs.
          </Typography>
          {owaspReference && Object.entries(owaspReference.categories).map(([id, category]) => (
            <Accordion key={id}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                  <Chip label={id} size="small" color="secondary" />
                  <Typography variant="subtitle2">{category.name}</Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" paragraph>
                  {category.description}
                </Typography>
                <Button
                  size="small"
                  href={category.url}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  View Full Details on OWASP
                </Button>
              </AccordionDetails>
            </Accordion>
          ))}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOwaspOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* Save Preset Dialog */}
      <Dialog open={newPresetOpen} onClose={() => setNewPresetOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <PresetIcon color="primary" />
          Save Target as Preset
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Save your current configuration for quick access later.
          </Typography>
          <TextField
            fullWidth
            label="Preset Name"
            value={newPresetName}
            onChange={(e) => setNewPresetName(e.target.value)}
            sx={{ mb: 2 }}
            placeholder="e.g., Production API, Lab VM 1"
          />
          <TextField
            fullWidth
            label="Description (optional)"
            value={newPresetDescription}
            onChange={(e) => setNewPresetDescription(e.target.value)}
            multiline
            rows={2}
            placeholder="Brief description of this target"
          />
          <Box sx={{ mt: 2, p: 2, bgcolor: "background.default", borderRadius: 1 }}>
            <Typography variant="subtitle2" gutterBottom>Will save:</Typography>
            <Typography variant="body2" color="text.secondary">
              • Base URL: {baseUrl || "(not set)"}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              • Endpoints: {endpoints.filter(e => e.url).length} configured
            </Typography>
            <Typography variant="body2" color="text.secondary">
              • Auth: {authType !== "none" ? authType : "none"}
            </Typography>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewPresetOpen(false)}>Cancel</Button>
          <Button 
            onClick={saveAsPreset} 
            variant="contained"
            disabled={!newPresetName || !baseUrl}
          >
            Save Preset
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
