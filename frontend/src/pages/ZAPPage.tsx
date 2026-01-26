import React, { useState, useEffect, useRef } from "react";
import {
  Box,
  Paper,
  Typography,
  Button,
  TextField,
  Grid,
  Chip,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  LinearProgress,
  Card,
  CardContent,
  IconButton,
  Collapse,
  Badge,
  alpha,
  List,
  ListItem,
  ListItemText,
  FormControlLabel,
  Switch,
  Tooltip,
  Zoom,
  Fade,
  keyframes,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tabs,
  Tab,
  Divider,
  Menu,
  ListItemIcon,
} from "@mui/material";
import { Link } from "react-router-dom";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StopIcon from "@mui/icons-material/Stop";
import RefreshIcon from "@mui/icons-material/Refresh";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import BugReportIcon from "@mui/icons-material/BugReport";
import HttpIcon from "@mui/icons-material/Http";
import SettingsIcon from "@mui/icons-material/Settings";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import RadarIcon from "@mui/icons-material/Radar";
import AssessmentIcon from "@mui/icons-material/Assessment";
import DownloadIcon from "@mui/icons-material/Download";
import DeleteIcon from "@mui/icons-material/Delete";
import VisibilityIcon from "@mui/icons-material/Visibility";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import SchoolIcon from "@mui/icons-material/School";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import InfoIcon from "@mui/icons-material/Info";
import SecurityIcon from "@mui/icons-material/Security";
import SpeedIcon from "@mui/icons-material/Speed";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import LinkIcon from "@mui/icons-material/Link";
import WarningIcon from "@mui/icons-material/Warning";
import BuildIcon from "@mui/icons-material/Build";
import TimelineIcon from "@mui/icons-material/Timeline";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import AccessTimeIcon from "@mui/icons-material/AccessTime";
import PsychologyIcon from "@mui/icons-material/Psychology";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import SummarizeIcon from "@mui/icons-material/Summarize";
import TableChartIcon from "@mui/icons-material/TableChart";
import VerifiedIcon from "@mui/icons-material/Verified";
import ReportProblemIcon from "@mui/icons-material/ReportProblem";
import ThumbUpIcon from "@mui/icons-material/ThumbUp";
import ThumbDownIcon from "@mui/icons-material/ThumbDown";
import FilterListIcon from "@mui/icons-material/FilterList";
import SortIcon from "@mui/icons-material/Sort";
import CategoryIcon from "@mui/icons-material/Category";
import DomainIcon from "@mui/icons-material/Domain";
import ChatIcon from "@mui/icons-material/Chat";
import SendIcon from "@mui/icons-material/Send";
import CableIcon from "@mui/icons-material/Cable";
import HubIcon from "@mui/icons-material/Hub";
import CodeIcon from "@mui/icons-material/Code";
import EditNoteIcon from "@mui/icons-material/EditNote";
import ApiIcon from "@mui/icons-material/Api";
import TuneIcon from "@mui/icons-material/Tune";
import AddIcon from "@mui/icons-material/Add";
import FolderOpenIcon from "@mui/icons-material/FolderOpen";
import ExploreIcon from "@mui/icons-material/Explore";
import TerminalIcon from "@mui/icons-material/Terminal";
import ShieldIcon from "@mui/icons-material/Shield";
import DashboardIcon from "@mui/icons-material/Dashboard";
import BarChartIcon from "@mui/icons-material/BarChart";
import PieChartIcon from "@mui/icons-material/PieChart";
import DonutLargeIcon from "@mui/icons-material/DonutLarge";
import PauseIcon from "@mui/icons-material/Pause";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import ReactMarkdown from "react-markdown";
import {
  zapClient,
  ZAPScanRequest,
  ZAPScanProgress,
  ZAPAlert,
  ZAPFinding,
  ZAPScanSummary,
  ZAPScanDetail,
  ZAPAIAnalysis,
  ZAPWebSocketChannel,
  ZAPWebSocketMessage,
  ZAPGraphQLOptions,
  ZAPScanPolicy,
  ZAPScanner,
  ZAPMessageSummary,
  ZAPContextDetails,
  ZAPScript,
  ZAPScriptEngine,
} from "../api/client";

// Keyframe animations
const radarSweep = keyframes`
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.7; transform: scale(1.05); }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 5px rgba(16, 185, 129, 0.3), 0 0 10px rgba(16, 185, 129, 0.2); }
  50% { box-shadow: 0 0 20px rgba(16, 185, 129, 0.5), 0 0 30px rgba(16, 185, 129, 0.3); }
`;

const scanLine = keyframes`
  0% { top: 0%; opacity: 1; }
  100% { top: 100%; opacity: 0; }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
`;

// Helper to convert localhost/127.0.0.1 to host.docker.internal
const convertToInternalUrl = (url: string): string => {
  if (!url) return url;
  // Replace localhost and 127.0.0.1 with host.docker.internal
  return url
    .replace(/localhost/gi, "host.docker.internal")
    .replace(/127\.0\.0\.1/g, "host.docker.internal");
};

// Check if URL needs conversion for internal scanning
const needsInternalConversion = (url: string): boolean => {
  if (!url) return false;
  const lowerUrl = url.toLowerCase();
  return lowerUrl.includes("localhost") || lowerUrl.includes("127.0.0.1");
};

// Beginner's Guide Content
const GUIDE_CONTENT = {
  targetUrl: {
    title: "🎯 Target URL",
    description: "The web application URL you want to scan for security vulnerabilities.",
    examples: [
      "https://example.com",
      "http://host.docker.internal:8080 (for localhost)",
      "http://192.168.1.100:3000 (internal network)"
    ],
    tips: [
      "Always get permission before scanning!",
      "For localhost apps, use host.docker.internal instead",
      "Internal IPs (192.168.x.x, 10.x.x.x) work directly",
      "Include the protocol (http:// or https://)"
    ]
  },
  scanType: {
    title: "🔍 Scan Type",
    description: "Different scanning methods for different purposes:",
    options: {
      spider: {
        name: "🕷️ Spider Only",
        description: "Crawls the website to discover all pages and links. Fast but doesn't test for vulnerabilities.",
        bestFor: "Quick reconnaissance, mapping site structure",
        duration: "1-5 minutes"
      },
      ajax_spider: {
        name: "⚡ AJAX Spider",
        description: "Advanced crawler for JavaScript-heavy single-page applications (SPAs).",
        bestFor: "React, Angular, Vue.js apps",
        duration: "5-15 minutes"
      },
      active_scan: {
        name: "🎯 Active Scan",
        description: "Actively tests discovered pages for vulnerabilities by sending attack payloads.",
        bestFor: "Finding SQL injection, XSS, etc.",
        duration: "15-60 minutes"
      },
      full_scan: {
        name: "🔥 Full Scan",
        description: "Complete scan: Spider + Active Scan. Most thorough but takes longest.",
        bestFor: "Comprehensive security assessment",
        duration: "30-120 minutes"
      }
    }
  },
  maxDepth: {
    title: "📊 Max Depth",
    description: "How many levels deep the scanner should crawl from the starting URL.",
    examples: [
      { value: "1-3", use: "Quick scan of main pages only" },
      { value: "5", use: "Standard depth (recommended for most sites)" },
      { value: "10+", use: "Deep scan for complex applications" }
    ],
    tips: [
      "Higher depth = more pages scanned = longer time",
      "Start with 5 and adjust based on results",
      "Very deep scans can take hours on large sites"
    ]
  },
  recurse: {
    title: "🔄 Recurse",
    description: "Whether to follow links and scan discovered pages recursively.",
    options: {
      enabled: "Scanner will follow all links and scan every page it finds",
      disabled: "Only scans the exact URL provided, ignoring links"
    },
    tips: [
      "Enable for full site coverage",
      "Disable when testing a specific page only"
    ]
  }
};

const ZAPPage: React.FC = () => {
  // ZAP State
  const [zapTargetUrl, setZapTargetUrl] = useState("");
  const [zapScanTitle, setZapScanTitle] = useState("");
  const [zapScanType, setZapScanType] = useState<"spider" | "ajax_spider" | "active_scan" | "full_scan">("full_scan");
  const [zapMaxDepth, setZapMaxDepth] = useState(5);
  const [zapRecurse, setZapRecurse] = useState(true);
  const [zapIsRunning, setZapIsRunning] = useState(false);
  const [zapProgress, setZapProgress] = useState<ZAPScanProgress | null>(null);
  const [zapOverallProgress, setZapOverallProgress] = useState(0);
  const [zapAlerts, setZapAlerts] = useState<(ZAPAlert | ZAPFinding)[]>([]);
  const [zapScans, setZapScans] = useState<ZAPScanSummary[]>([]);
  const [zapSelectedScan, setZapSelectedScan] = useState<ZAPScanDetail | null>(null);
  const [zapHealthy, setZapHealthy] = useState<boolean | null>(null);
  const [zapLoading, setZapLoading] = useState(false);
  const [zapAlertFilter, setZapAlertFilter] = useState<string>("all");
  const [zapError, setZapError] = useState<string | null>(null);
  const zapAbortRef = useRef<AbortController | null>(null);
  
  // Refs to track latest values for closure access in callbacks
  const zapProgressRef = useRef<ZAPScanProgress | null>(null);
  const zapAlertsRef = useRef<(ZAPAlert | ZAPFinding)[]>([]);
  const zapScanTitleRef = useRef<string>("");
  
  // Helper to calculate overall progress based on scan phase
  const calculateOverallProgress = (progress: ZAPScanProgress): number => {
    // Phase weights for full_scan: spider=20%, ajax_spider=15%, active_scan=60%, passive/results=5%
    const phaseWeights = {
      'initialization': { base: 0, weight: 2 },
      'access_target': { base: 2, weight: 3 },
      'spider': { base: 5, weight: 15 },
      'ajax_spider': { base: 20, weight: 10 },
      'active_scan': { base: 30, weight: 60 },
      'passive_scan': { base: 90, weight: 5 },
      'collecting_results': { base: 95, weight: 5 },
    };
    
    const eventType = progress.type;
    const phase = progress.phase || '';
    const phaseProgress = progress.progress || 0;
    
    // Handle specific event types
    if (eventType === 'spider_progress') {
      const w = phaseWeights['spider'];
      return Math.min(w.base + Math.round((phaseProgress / 100) * w.weight), 100);
    }
    if (eventType === 'spider_complete') {
      return phaseWeights['ajax_spider'].base;
    }
    if (eventType === 'ajax_spider_progress') {
      // AJAX spider is time-based, estimate based on elapsed time (max 10 mins typical)
      const elapsed = (progress as any).elapsed_seconds || 0;
      const estimatedTotal = 600; // 10 minutes
      const ajaxProgress = Math.min((elapsed / estimatedTotal) * 100, 100);
      const w = phaseWeights['ajax_spider'];
      return Math.min(w.base + Math.round((ajaxProgress / 100) * w.weight), 100);
    }
    if (eventType === 'ajax_spider_complete') {
      return phaseWeights['active_scan'].base;
    }
    if (eventType === 'active_scan_progress') {
      const w = phaseWeights['active_scan'];
      return Math.min(w.base + Math.round((phaseProgress / 100) * w.weight), 100);
    }
    if (eventType === 'active_scan_complete') {
      return phaseWeights['passive_scan'].base;
    }
    if (eventType === 'passive_scan_progress') {
      return 92;
    }
    if (eventType === 'scan_complete' || eventType === 'findings') {
      return 100;
    }
    if (eventType === 'phase_started') {
      const w = phaseWeights[phase as keyof typeof phaseWeights];
      return w ? w.base : 0;
    }
    
    return 0;
  };
  
  // ZAP AI Analysis state
  const [zapAiAnalysis, setZapAiAnalysis] = useState<ZAPAIAnalysis | null>(null);
  const [zapAiAnalyzing, setZapAiAnalyzing] = useState(false);
  const [zapAiError, setZapAiError] = useState<string | null>(null);
  const [zapShowAiPanel, setZapShowAiPanel] = useState(false);
  
  // Beginner's Guide Mode
  const [beginnerMode, setBeginnerMode] = useState(false);
  const [expandedGuide, setExpandedGuide] = useState<string | null>(null);
  
  // Tab state
  const [activeTab, setActiveTab] = useState(0);
  
  // AI Analysis Tab state
  const [aiAnalysisTab, setAiAnalysisTab] = useState(0);
  
  // Export menu state
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  
  // Results tab state
  const [resultsTab, setResultsTab] = useState(0);
  
  // Alert validation state
  const [validatingAlertId, setValidatingAlertId] = useState<string | null>(null);
  const [alertValidations, setAlertValidations] = useState<Record<string, { validated: boolean; falsePositive: boolean; notes: string }>>({});
  
  // Expanded alert state
  const [expandedAlertIndex, setExpandedAlertIndex] = useState<number | null>(null);
  
  // AI Context for analysis
  const [aiContext, setAiContext] = useState("");
  
  // AI Chat state
  const [chatMessages, setChatMessages] = useState<Array<{ role: 'user' | 'assistant'; content: string }>>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const chatContainerRef = useRef<HTMLDivElement>(null);
  
  // WebSocket Testing state
  const [wsChannels, setWsChannels] = useState<ZAPWebSocketChannel[]>([]);
  const [wsMessages, setWsMessages] = useState<ZAPWebSocketMessage[]>([]);
  const [wsSelectedChannel, setWsSelectedChannel] = useState<number | null>(null);
  const [wsLoading, setWsLoading] = useState(false);
  const [wsSendMessage, setWsSendMessage] = useState("");
  const [wsExpanded, setWsExpanded] = useState(false);
  
  // GraphQL Testing state
  const [gqlEndpointUrl, setGqlEndpointUrl] = useState("");
  const [gqlSchemaContent, setGqlSchemaContent] = useState("");
  const [gqlOptions, setGqlOptions] = useState<ZAPGraphQLOptions | null>(null);
  const [gqlLoading, setGqlLoading] = useState(false);
  const [gqlImportStatus, setGqlImportStatus] = useState<string | null>(null);
  const [gqlExpanded, setGqlExpanded] = useState(false);
  
  // Manual Request Editor state
  const [reqEditorExpanded, setReqEditorExpanded] = useState(false);
  const [reqEditorContent, setReqEditorContent] = useState(`GET /api/example HTTP/1.1\nHost: example.com\nAccept: application/json\n\n`);
  const [reqEditorFollowRedirects, setReqEditorFollowRedirects] = useState(true);
  const [reqEditorLoading, setReqEditorLoading] = useState(false);
  const [reqEditorResponse, setReqEditorResponse] = useState<string | null>(null);
  const [reqHistory, setReqHistory] = useState<ZAPMessageSummary[]>([]);
  
  // OpenAPI/Swagger Import state
  const [openApiExpanded, setOpenApiExpanded] = useState(false);
  const [openApiUrl, setOpenApiUrl] = useState("");
  const [openApiContent, setOpenApiContent] = useState("");
  const [openApiTargetUrl, setOpenApiTargetUrl] = useState("");
  const [openApiLoading, setOpenApiLoading] = useState(false);
  const [openApiStatus, setOpenApiStatus] = useState<string | null>(null);
  
  // Custom Scan Policies state
  const [policiesExpanded, setPoliciesExpanded] = useState(false);
  const [scanPolicies, setScanPolicies] = useState<ZAPScanPolicy[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>(null);
  const [policyScanners, setPolicyScanners] = useState<ZAPScanner[]>([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [newPolicyName, setNewPolicyName] = useState("");
  
  // Context Management state
  const [contextsExpanded, setContextsExpanded] = useState(false);
  const [contexts, setContexts] = useState<string[]>([]);
  const [selectedContext, setSelectedContext] = useState<string | null>(null);
  const [contextDetails, setContextDetails] = useState<any>(null);
  const [contextsLoading, setContextsLoading] = useState(false);
  const [newContextName, setNewContextName] = useState("");
  const [newIncludeRegex, setNewIncludeRegex] = useState("");
  const [newExcludeRegex, setNewExcludeRegex] = useState("");
  const [availableTechnologies, setAvailableTechnologies] = useState<string[]>([]);
  
  // Forced Browse state
  const [forcedBrowseExpanded, setForcedBrowseExpanded] = useState(false);
  const [forcedBrowseUrl, setForcedBrowseUrl] = useState("");
  const [forcedBrowseRecursive, setForcedBrowseRecursive] = useState(true);
  const [forcedBrowseProgress, setForcedBrowseProgress] = useState(0);
  const [forcedBrowseStatus, setForcedBrowseStatus] = useState<string>("idle");
  const [forcedBrowseLoading, setForcedBrowseLoading] = useState(false);
  const [forcedBrowseSessionId, setForcedBrowseSessionId] = useState<string | null>(null);
  const [forcedBrowseResults, setForcedBrowseResults] = useState<any[]>([]);
  const [forcedBrowseThreads, setForcedBrowseThreads] = useState(10);
  const [selectedWordlist, setSelectedWordlist] = useState("");
  const [wordlists, setWordlists] = useState<string[]>([]);
  const [defaultWordlist, setDefaultWordlist] = useState("");
  const [wordlistsError, setWordlistsError] = useState<string | null>(null);
  const [wordlistsLoading, setWordlistsLoading] = useState(false);
  
  // Script Console state
  const [scriptsExpanded, setScriptsExpanded] = useState(false);
  const [scripts, setScripts] = useState<any[]>([]);
  const [scriptEngines, setScriptEngines] = useState<any[]>([]);
  const [scriptTypes, setScriptTypes] = useState<string[]>([]);
  const [scriptsLoading, setScriptsLoading] = useState(false);
  const [scriptVariables, setScriptVariables] = useState<{ global_vars: Record<string, string>; custom_vars: Record<string, string> }>({ global_vars: {}, custom_vars: {} });
  const [newScriptVarKey, setNewScriptVarKey] = useState("");
  const [newScriptVarValue, setNewScriptVarValue] = useState("");
  
  // Results panel ref for auto-scroll
  const resultsPanelRef = useRef<HTMLDivElement>(null);
  
  // Check ZAP health on mount
  useEffect(() => {
    const checkZapHealth = async () => {
      try {
        const health = await zapClient.getHealth();
        setZapHealthy(health.available);
      } catch {
        setZapHealthy(false);
      }
    };
    checkZapHealth();
    loadZapScans();
  }, []);

  // Load ZAP scans
  const loadZapScans = async () => {
    setZapLoading(true);
    try {
      const result = await zapClient.getSavedScans();
      // Sort by date (newest first)
      const sortedScans = [...result.scans].sort((a, b) => {
        const dateA = a.created_at ? new Date(a.created_at).getTime() : 0;
        const dateB = b.created_at ? new Date(b.created_at).getTime() : 0;
        return dateB - dateA;
      });
      setZapScans(sortedScans);
    } catch (err: any) {
      setZapError(err.message || "Failed to load scans");
    } finally {
      setZapLoading(false);
    }
  };

  // Start ZAP scan
  const startZapScan = async () => {
    if (!zapTargetUrl || !zapHealthy) return;
    
    setZapIsRunning(true);
    setZapError(null);
    setZapAlerts([]);
    setZapProgress(null);
    setZapOverallProgress(0);
    setZapAiAnalysis(null);
    setZapShowAiPanel(false);
    
    const request: ZAPScanRequest = {
      target_url: zapTargetUrl,
      scan_type: zapScanType,
      max_depth: zapMaxDepth,
      recurse: zapRecurse,
    };
    
    // Start scan with callback-based streaming progress
    const controller = zapClient.startScan(
      request,
      (progress: ZAPScanProgress) => {
        setZapProgress(progress);
        zapProgressRef.current = progress;
        // Calculate and update overall progress
        const overallPct = calculateOverallProgress(progress);
        setZapOverallProgress(overallPct);
        // Capture alerts from SSE events (direct alerts or from 'findings' event type)
        if (progress.alerts) {
          setZapAlerts(progress.alerts);
          zapAlertsRef.current = progress.alerts;
        }
        // Handle 'findings' event type from backend (contains actual vulnerability findings)
        if (progress.type === 'findings' && (progress as any).findings) {
          const findings = (progress as any).findings as ZAPFinding[];
          setZapAlerts(findings);
          zapAlertsRef.current = findings;
          console.log("Captured findings from SSE:", findings.length);
        }
      },
      (error: string) => {
        setZapError(error);
        setZapIsRunning(false);
      },
      async () => {
        // On complete - auto-save scan and refresh list using refs for latest values
        const currentProgress = zapProgressRef.current;
        const currentTitle = zapScanTitleRef.current;
        
        let savedScanId: number | null = null;
        
        // Always try to save if we have a session ID
        if (currentProgress?.session_id) {
          // Use the scan title from ref to ensure we get the user's entered name
          const title = currentTitle.trim() 
            ? currentTitle.trim()
            : `${new URL(zapTargetUrl).hostname} - ${new Date().toLocaleString()}`;
          try {
            const saveResult = await zapClient.saveScan(currentProgress.session_id, title);
            savedScanId = saveResult.scan_id;
            console.log("Scan saved with ID:", savedScanId, "Title:", title);
          } catch (err) {
            console.error("Failed to save scan:", err);
          }
        }
        
        // Refresh the scans list
        await loadZapScans();
        setZapIsRunning(false);
        setZapScanTitle(""); // Clear title after save
        zapScanTitleRef.current = "";
        
        // Auto-load the saved scan to show results below
        // If we have a savedScanId, use it; otherwise load the most recent scan
        let scanToLoadId = savedScanId;
        if (!scanToLoadId) {
          // Get the most recent scan from the refreshed list
          try {
            const scansResult = await zapClient.getSavedScans(0, 1);
            if (scansResult.scans.length > 0) {
              scanToLoadId = scansResult.scans[0].id;
            }
          } catch (err) {
            console.error("Failed to get recent scans:", err);
          }
        }
        
        if (scanToLoadId) {
          try {
            const detail = await zapClient.getSavedScan(scanToLoadId);
            setZapSelectedScan(detail);
            
            // Use alerts from DB if available, otherwise fall back to SSE captured alerts
            const dbAlerts = detail.alerts || [];
            const sseAlerts = zapAlertsRef.current || [];
            const alertsToUse = dbAlerts.length > 0 ? dbAlerts : sseAlerts;
            
            setZapAlerts(alertsToUse);
            zapAlertsRef.current = alertsToUse;
            console.log("Auto-loaded scan:", scanToLoadId, "DB alerts:", dbAlerts.length, "SSE alerts:", sseAlerts.length);
            
            // Always auto-trigger AI analysis regardless of alert count
            console.log("Auto-triggering AI analysis with", alertsToUse.length, "alerts");
            setZapAiAnalyzing(true);
            try {
              // Convert all alerts to ZAPAlert format for AI analysis
              const alertsForAnalysis: ZAPAlert[] = alertsToUse.slice(0, 50).map((alert): ZAPAlert => {
                // If it looks like a ZAPAlert with required properties, cast it
                if ('name' in alert && 'risk' in alert && 'url' in alert && 'risk_code' in alert) {
                  return alert as unknown as ZAPAlert;
                }
                // Convert from ZAPFinding format
                const finding = alert as ZAPFinding;
                const severity = ('severity' in alert ? (alert as ZAPFinding).severity : (alert as { risk?: string }).risk) || 'info';
                return {
                  id: finding.id || '',
                  name: ('title' in alert ? (alert as ZAPFinding).title : (alert as { name?: string }).name) || 'Unknown',
                  risk: severity,
                  risk_code: severity === 'high' ? 3 : severity === 'medium' ? 2 : severity === 'low' ? 1 : 0,
                  confidence: 'medium',
                  url: ('endpoint' in alert ? (alert as ZAPFinding).endpoint : (alert as { url?: string }).url) || '',
                  method: 'GET',
                  parameter: finding.parameter || '',
                  evidence: Array.isArray(finding.evidence) ? finding.evidence[0] || '' : (finding.evidence as unknown as string) || '',
                  description: finding.description || '',
                  solution: finding.recommendation || '',
                  cwe_id: finding.cwe_id?.toString() || '',
                };
              });
              const aiResult = await zapClient.aiAnalyze(alertsForAnalysis, detail.target_url || zapTargetUrl);
              setZapAiAnalysis(aiResult);
              setZapShowAiPanel(true);
              console.log("AI analysis completed successfully");
            } catch (err) {
              console.error("Auto AI analysis failed:", err);
            } finally {
              setZapAiAnalyzing(false);
            }
          } catch (err) {
            console.error("Failed to load saved scan:", err);
          }
        }
        
        // Auto-scroll to results and show Executive Summary tab
        setResultsTab(0);
        setTimeout(() => {
          resultsPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 300);
      }
    );
    
    zapAbortRef.current = controller;
  };

  // Stop ZAP scan
  const stopZapScan = async () => {
    if (zapAbortRef.current) {
      zapAbortRef.current.abort();
    }
    if (zapProgress?.session_id) {
      try {
        await zapClient.stopScan(zapProgress.session_id);
      } catch (err) {
        console.error("Failed to stop scan:", err);
      }
    }
    setZapIsRunning(false);
  };

  // View scan details
  const viewZapScanDetails = async (scanId: number) => {
    setZapLoading(true);
    try {
      const detail = await zapClient.getSavedScan(scanId);
      setZapSelectedScan(detail);
      setZapAlerts(detail.alerts || []);
      
      // Auto-scroll to results and show Executive Summary tab
      setResultsTab(0);
      setTimeout(() => {
        resultsPanelRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }, 300);
    } catch (err: any) {
      setZapError(err.message || "Failed to load scan details");
    } finally {
      setZapLoading(false);
    }
  };

  // Delete scan
  const deleteZapScan = async (scanId: number) => {
    try {
      await zapClient.deleteSavedScan(scanId);
      await loadZapScans();
      if (zapSelectedScan?.id === scanId) {
        setZapSelectedScan(null);
      }
    } catch (err: any) {
      setZapError(err.message || "Failed to delete scan");
    }
  };

  // AI Analysis
  const runZapAiAnalysis = async () => {
    if (zapAlerts.length === 0) return;
    
    setZapAiAnalyzing(true);
    setZapAiError(null);
    
    try {
      // Fetch current stats to include in report
      let scanStats;
      try {
        const statsData = await zapClient.getStatsOverview();
        scanStats = {
          total_messages: statsData.total_messages || 0,
          urls_discovered: statsData.sites_count || 0,
          hosts_count: statsData.hosts_count || 0,
          passive_scan_queue: statsData.passive_scan_queue || 0,
        };
      } catch {
        // Stats fetch failed, continue without
      }
      
      // Convert alerts to ZAPAlert format if needed
      const alertsForAnalysis: ZAPAlert[] = zapAlerts.slice(0, 50).map((alert): ZAPAlert => {
        if ('risk' in alert) {
          return alert;
        }
        // Convert ZAPFinding to ZAPAlert
        return {
          id: alert.id,
          name: alert.title,
          risk: alert.severity,
          risk_code: alert.severity === 'High' || alert.severity === 'Critical' ? 3 : 
                     alert.severity === 'Medium' ? 2 : 
                     alert.severity === 'Low' ? 1 : 0,
          confidence: 'Medium',
          url: alert.endpoint,
          method: 'GET',
          description: alert.description,
          solution: alert.recommendation,
          cwe_id: alert.cwe_id,
        };
      });
      
      const analysis = await zapClient.aiAnalyze(
        alertsForAnalysis,
        zapTargetUrl || zapSelectedScan?.target_url || "",
        {
          includeExploitChains: true,
          includeRemediation: true,
          includeBusinessImpact: true,
          additionalContext: aiContext || undefined,
          scanStatistics: scanStats,
        }
      );
      setZapAiAnalysis(analysis);
      setZapShowAiPanel(true);
      // Initialize chat with context
      setChatMessages([]);
    } catch (err: any) {
      setZapAiError(err.message || "AI analysis failed");
    } finally {
      setZapAiAnalyzing(false);
    }
  };
  
  // AI Chat function
  const sendChatMessage = async () => {
    if (!chatInput.trim() || chatLoading) return;
    
    const userMessage = chatInput.trim();
    setChatInput("");
    setChatMessages(prev => [...prev, { role: 'user', content: userMessage }]);
    setChatLoading(true);
    
    try {
      // Build context from scan results and AI analysis
      const contextSummary = `
Target: ${zapTargetUrl || zapSelectedScan?.target_url || 'Unknown'}
Total Alerts: ${zapAlerts.length}
High/Critical: ${zapAlerts.filter(a => ['high', 'critical'].includes(getAlertRisk(a).toLowerCase())).length}
Medium: ${zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'medium').length}
Low: ${zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'low').length}

${aiContext ? `Additional Context: ${aiContext}` : ''}

${zapAiAnalysis ? `AI Analysis Summary: ${zapAiAnalysis.summary}` : ''}

Top Vulnerabilities:
${Object.entries(groupedAlerts).slice(0, 10).map(([name, alerts]) => 
  `- ${name} (${getAlertRisk(alerts[0])}, ${alerts.length} instances)`
).join('\n')}
      `.trim();
      
      // Call AI chat endpoint
      const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/zap/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
        body: JSON.stringify({
          message: userMessage,
          context: contextSummary,
          history: chatMessages.slice(-10),
          alerts: zapAlerts.slice(0, 20).map(a => ({
            name: getAlertName(a),
            risk: getAlertRisk(a),
            url: getAlertUrl(a),
            description: a.description?.slice(0, 200),
          })),
        }),
      });
      
      if (!response.ok) throw new Error('Chat request failed');
      
      const data = await response.json();
      setChatMessages(prev => [...prev, { role: 'assistant', content: data.response }]);
    } catch (err) {
      setChatMessages(prev => [...prev, { 
        role: 'assistant', 
        content: 'Sorry, I encountered an error processing your request. Please try again.' 
      }]);
    } finally {
      setChatLoading(false);
    }
  };
  
  // Scroll chat to bottom
  useEffect(() => {
    if (chatContainerRef.current) {
      chatContainerRef.current.scrollTop = chatContainerRef.current.scrollHeight;
    }
  }, [chatMessages]);

  // =========================================================================
  // WebSocket Testing Functions
  // =========================================================================
  
  // Load WebSocket channels
  const loadWsChannels = async () => {
    setWsLoading(true);
    try {
      const result = await zapClient.getWebSocketChannels();
      setWsChannels(result.channels);
      if (result.channels.length > 0 && !wsSelectedChannel) {
        setWsSelectedChannel(result.channels[0].id);
      }
    } catch (err: any) {
      console.error("Failed to load WebSocket channels:", err);
    } finally {
      setWsLoading(false);
    }
  };
  
  // Load WebSocket messages for selected channel
  const loadWsMessages = async () => {
    if (wsSelectedChannel === null) return;
    setWsLoading(true);
    try {
      const result = await zapClient.getWebSocketMessages(wsSelectedChannel, 0, 100);
      setWsMessages(result.messages);
    } catch (err: any) {
      console.error("Failed to load WebSocket messages:", err);
    } finally {
      setWsLoading(false);
    }
  };
  
  // Send WebSocket message
  const sendWsMessage = async () => {
    if (!wsSendMessage.trim() || wsSelectedChannel === null) return;
    try {
      await zapClient.sendWebSocketMessage(wsSelectedChannel, wsSendMessage, true);
      setWsSendMessage("");
      // Reload messages after sending
      loadWsMessages();
    } catch (err: any) {
      setZapError(`Failed to send WebSocket message: ${err.message}`);
    }
  };
  
  // Load WebSocket data when expanded
  useEffect(() => {
    if (wsExpanded && wsChannels.length === 0) {
      loadWsChannels();
    }
  }, [wsExpanded]);
  
  // Load messages when channel changes
  useEffect(() => {
    if (wsSelectedChannel !== null) {
      loadWsMessages();
    }
  }, [wsSelectedChannel]);
  
  // =========================================================================
  // GraphQL Testing Functions
  // =========================================================================
  
  // Load GraphQL options
  const loadGqlOptions = async () => {
    setGqlLoading(true);
    try {
      const options = await zapClient.getGraphQLOptions();
      setGqlOptions(options);
    } catch (err: any) {
      console.error("Failed to load GraphQL options:", err);
    } finally {
      setGqlLoading(false);
    }
  };
  
  // Import GraphQL schema via introspection
  const importGqlUrl = async () => {
    if (!gqlEndpointUrl.trim()) return;
    setGqlLoading(true);
    setGqlImportStatus(null);
    try {
      const result = await zapClient.importGraphQLUrl(gqlEndpointUrl);
      setGqlImportStatus(`✅ Schema imported from ${result.url}`);
    } catch (err: any) {
      setGqlImportStatus(`❌ Failed to import: ${err.message}`);
    } finally {
      setGqlLoading(false);
    }
  };
  
  // Import GraphQL schema from SDL content
  const importGqlSchema = async () => {
    if (!gqlSchemaContent.trim() || !gqlEndpointUrl.trim()) return;
    setGqlLoading(true);
    setGqlImportStatus(null);
    try {
      const result = await zapClient.importGraphQLSchema(gqlSchemaContent, gqlEndpointUrl);
      setGqlImportStatus(`✅ Schema imported for ${result.endpoint_url}`);
    } catch (err: any) {
      setGqlImportStatus(`❌ Failed to import: ${err.message}`);
    } finally {
      setGqlLoading(false);
    }
  };
  
  // Load GraphQL options when expanded
  useEffect(() => {
    if (gqlExpanded && !gqlOptions) {
      loadGqlOptions();
    }
  }, [gqlExpanded]);

  // =========================================================================
  // Manual Request Editor Functions
  // =========================================================================
  
  // Send manual request
  const sendManualRequest = async () => {
    if (!reqEditorContent.trim()) return;
    setReqEditorLoading(true);
    setReqEditorResponse(null);
    try {
      const result = await zapClient.sendRequest(reqEditorContent, reqEditorFollowRedirects);
      setReqEditorResponse(JSON.stringify(result, null, 2));
      // Reload message history
      loadRequestHistory();
    } catch (err: any) {
      setReqEditorResponse(`Error: ${err.message}`);
    } finally {
      setReqEditorLoading(false);
    }
  };
  
  // Load request history
  const loadRequestHistory = async () => {
    try {
      const result = await zapClient.getMessages(undefined, 0, 20);
      setReqHistory(result.messages);
    } catch (err: any) {
      console.error("Failed to load request history:", err);
    }
  };
  
  // Load history when expanded
  useEffect(() => {
    if (reqEditorExpanded && reqHistory.length === 0) {
      loadRequestHistory();
    }
  }, [reqEditorExpanded]);
  
  // =========================================================================
  // OpenAPI/Swagger Import Functions
  // =========================================================================
  
  // Import OpenAPI from URL
  const importOpenApiUrl = async () => {
    if (!openApiUrl.trim()) return;
    setOpenApiLoading(true);
    setOpenApiStatus(null);
    try {
      const result = await zapClient.importOpenAPIUrl(openApiUrl);
      setOpenApiStatus(`✅ API definition imported from ${result.url}`);
    } catch (err: any) {
      setOpenApiStatus(`❌ Failed to import: ${err.message}`);
    } finally {
      setOpenApiLoading(false);
    }
  };
  
  // Import OpenAPI from content
  const importOpenApiContent = async () => {
    if (!openApiContent.trim() || !openApiTargetUrl.trim()) return;
    setOpenApiLoading(true);
    setOpenApiStatus(null);
    try {
      const result = await zapClient.importOpenAPIFile(openApiContent, openApiTargetUrl);
      setOpenApiStatus(`✅ API definition imported for ${result.target_url}`);
    } catch (err: any) {
      setOpenApiStatus(`❌ Failed to import: ${err.message}`);
    } finally {
      setOpenApiLoading(false);
    }
  };
  
  // =========================================================================
  // Custom Scan Policies Functions
  // =========================================================================
  
  // Load scan policies
  const loadScanPolicies = async () => {
    setPoliciesLoading(true);
    try {
      const result = await zapClient.getScanPolicies();
      setScanPolicies(result.policies);
    } catch (err: any) {
      console.error("Failed to load policies:", err);
    } finally {
      setPoliciesLoading(false);
    }
  };
  
  // Create new policy
  const createPolicy = async () => {
    if (!newPolicyName.trim()) return;
    setPoliciesLoading(true);
    try {
      await zapClient.createScanPolicy(newPolicyName, "MEDIUM", "MEDIUM");
      setNewPolicyName("");
      loadScanPolicies();
    } catch (err: any) {
      setZapError(`Failed to create policy: ${err.message}`);
    } finally {
      setPoliciesLoading(false);
    }
  };
  
  // Delete policy
  const deletePolicy = async (policyName: string) => {
    if (!confirm(`Delete policy "${policyName}"?`)) return;
    setPoliciesLoading(true);
    try {
      await zapClient.deleteScanPolicy(policyName);
      if (selectedPolicy === policyName) {
        setSelectedPolicy(null);
        setPolicyScanners([]);
      }
      loadScanPolicies();
    } catch (err: any) {
      setZapError(`Failed to delete policy: ${err.message}`);
    } finally {
      setPoliciesLoading(false);
    }
  };
  
  // Load policy scanners
  const loadPolicyScanners = async (policyName: string) => {
    setPoliciesLoading(true);
    try {
      const result = await zapClient.getPolicyScanners(policyName);
      setPolicyScanners(result.scanners);
    } catch (err: any) {
      console.error("Failed to load scanners:", err);
    } finally {
      setPoliciesLoading(false);
    }
  };
  
  // Toggle scanner
  const toggleScanner = async (scannerId: number, enabled: boolean) => {
    if (!selectedPolicy) return;
    try {
      await zapClient.updatePolicyScanner(selectedPolicy, scannerId, { enabled });
      // Update local state
      setPolicyScanners(prev => prev.map(s => 
        s.id === scannerId ? { ...s, enabled } : s
      ));
    } catch (err: any) {
      setZapError(`Failed to update scanner: ${err.message}`);
    }
  };
  
  // Load policies when expanded
  useEffect(() => {
    if (policiesExpanded && scanPolicies.length === 0) {
      loadScanPolicies();
    }
  }, [policiesExpanded]);
  
  // Load scanners when policy selected
  useEffect(() => {
    if (selectedPolicy) {
      loadPolicyScanners(selectedPolicy);
    }
  }, [selectedPolicy]);
  
  // =========================================================================
  // Context Management Functions
  // =========================================================================
  
  // Load contexts
  const loadContexts = async () => {
    setContextsLoading(true);
    try {
      const result = await zapClient.listContexts();
      setContexts(result.contexts);
    } catch (err: any) {
      console.error("Failed to load contexts:", err);
    } finally {
      setContextsLoading(false);
    }
  };
  
  // Load context details
  const loadContextDetails = async (contextName: string) => {
    setContextsLoading(true);
    try {
      const details = await zapClient.getContext(contextName);
      setContextDetails(details);
    } catch (err: any) {
      console.error("Failed to load context details:", err);
    } finally {
      setContextsLoading(false);
    }
  };
  
  // Create new context
  const createContext = async () => {
    if (!newContextName.trim()) return;
    setContextsLoading(true);
    try {
      await zapClient.createContext(newContextName);
      setNewContextName("");
      loadContexts();
    } catch (err: any) {
      setZapError(`Failed to create context: ${err.message}`);
    } finally {
      setContextsLoading(false);
    }
  };
  
  // Delete context
  const deleteContext = async (contextName: string) => {
    if (!confirm(`Delete context "${contextName}"?`)) return;
    setContextsLoading(true);
    try {
      await zapClient.deleteContext(contextName);
      if (selectedContext === contextName) {
        setSelectedContext(null);
        setContextDetails(null);
      }
      loadContexts();
    } catch (err: any) {
      setZapError(`Failed to delete context: ${err.message}`);
    } finally {
      setContextsLoading(false);
    }
  };
  
  // Add include regex
  const addIncludeRegex = async () => {
    if (!selectedContext || !newIncludeRegex.trim()) return;
    try {
      await zapClient.addContextInclude(selectedContext, newIncludeRegex);
      setNewIncludeRegex("");
      loadContextDetails(selectedContext);
    } catch (err: any) {
      setZapError(`Failed to add include regex: ${err.message}`);
    }
  };
  
  // Add exclude regex
  const addExcludeRegex = async () => {
    if (!selectedContext || !newExcludeRegex.trim()) return;
    try {
      await zapClient.addContextExclude(selectedContext, newExcludeRegex);
      setNewExcludeRegex("");
      loadContextDetails(selectedContext);
    } catch (err: any) {
      setZapError(`Failed to add exclude regex: ${err.message}`);
    }
  };
  
  // Load available technologies
  const loadTechnologies = async () => {
    try {
      const result = await zapClient.listTechnologies();
      setAvailableTechnologies(result.technologies);
    } catch (err: any) {
      console.error("Failed to load technologies:", err);
    }
  };
  
  // Load contexts when expanded
  useEffect(() => {
    if (contextsExpanded && contexts.length === 0) {
      loadContexts();
      loadTechnologies();
    }
  }, [contextsExpanded]);
  
  // Load context details when selected
  useEffect(() => {
    if (selectedContext) {
      loadContextDetails(selectedContext);
    }
  }, [selectedContext]);
  
  // =========================================================================
  // Forced Browse Functions
  // =========================================================================
  
  // Load wordlists
  const loadWordlists = async () => {
    setWordlistsLoading(true);
    setWordlistsError(null);
    try {
      const result = await zapClient.listWordlists();
      setWordlists(result.wordlists);
      setDefaultWordlist(result.default);
    } catch (err: any) {
      console.error("Failed to load wordlists:", err);
      // Check if it's a ZAP addon not installed error
      if (err.message?.includes("No Implementor") || err.message?.includes("500")) {
        setWordlistsError("Forced Browse addon not available in ZAP. This feature requires the ZAP Forced Browse add-on to be installed.");
      } else {
        setWordlistsError(err.message || "Failed to load wordlists");
      }
    } finally {
      setWordlistsLoading(false);
    }
  };
  
  // Start forced browse scan (local implementation)
  const startForcedBrowse = async () => {
    if (!forcedBrowseUrl.trim()) return;
    setForcedBrowseLoading(true);
    setForcedBrowseStatus("running");
    setForcedBrowseProgress(0);
    setForcedBrowseResults([]);
    
    try {
      // Use selected wordlist or default
      const wordlistToUse = selectedWordlist || defaultWordlist || "common.txt";
      const response = await zapClient.startForcedBrowse(
        forcedBrowseUrl, 
        forcedBrowseRecursive,
        wordlistToUse,
        forcedBrowseThreads
      );
      
      const sessionId = response.session_id;
      setForcedBrowseSessionId(sessionId);
      
      // Poll for progress and results
      const pollProgress = async () => {
        try {
          const status = await zapClient.getForcedBrowseStatus(sessionId);
          setForcedBrowseProgress(status.progress);
          setForcedBrowseStatus(status.status);
          
          // Also fetch results
          const resultsResponse = await zapClient.getForcedBrowseResults(sessionId);
          if (resultsResponse.results) {
            setForcedBrowseResults(resultsResponse.results);
          }
          
          if (status.status === "running" || status.status === "paused") {
            setTimeout(pollProgress, 2000);
          } else {
            setForcedBrowseLoading(false);
          }
        } catch (err) {
          setForcedBrowseStatus("error");
          setForcedBrowseLoading(false);
        }
      };
      pollProgress();
    } catch (err: any) {
      setZapError(`Failed to start forced browse: ${err.message}`);
      setForcedBrowseStatus("error");
      setForcedBrowseLoading(false);
    }
  };
  
  // Stop forced browse scan
  const stopForcedBrowse = async () => {
    if (!forcedBrowseSessionId) return;
    try {
      await zapClient.stopForcedBrowse(forcedBrowseSessionId);
      setForcedBrowseStatus("stopped");
      setForcedBrowseLoading(false);
    } catch (err: any) {
      setZapError(`Failed to stop forced browse: ${err.message}`);
    }
  };
  
  // Pause forced browse scan
  const pauseForcedBrowse = async () => {
    if (!forcedBrowseSessionId) return;
    try {
      await zapClient.pauseForcedBrowse(forcedBrowseSessionId);
      setForcedBrowseStatus("paused");
    } catch (err: any) {
      setZapError(`Failed to pause forced browse: ${err.message}`);
    }
  };
  
  // Resume forced browse scan
  const resumeForcedBrowse = async () => {
    if (!forcedBrowseSessionId) return;
    try {
      await zapClient.resumeForcedBrowse(forcedBrowseSessionId);
      setForcedBrowseStatus("running");
    } catch (err: any) {
      setZapError(`Failed to resume forced browse: ${err.message}`);
    }
  };
  
  // Load wordlists when expanded
  useEffect(() => {
    if (forcedBrowseExpanded && wordlists.length === 0) {
      loadWordlists();
    }
  }, [forcedBrowseExpanded]);
  
  // =========================================================================
  // Script Console Functions
  // =========================================================================
  
  // Load scripts
  const loadScripts = async () => {
    setScriptsLoading(true);
    try {
      const result = await zapClient.listScripts();
      setScripts(result.scripts);
    } catch (err: any) {
      console.error("Failed to load scripts:", err);
    } finally {
      setScriptsLoading(false);
    }
  };
  
  // Load script engines
  const loadScriptEngines = async () => {
    try {
      const result = await zapClient.listScriptEngines();
      setScriptEngines(result.engines);
    } catch (err: any) {
      console.error("Failed to load script engines:", err);
    }
  };
  
  // Load script types
  const loadScriptTypes = async () => {
    try {
      const result = await zapClient.listScriptTypes();
      setScriptTypes(result.types);
    } catch (err: any) {
      console.error("Failed to load script types:", err);
    }
  };
  
  // Load script variables
  const loadScriptVariables = async () => {
    try {
      const result = await zapClient.listScriptVariables();
      setScriptVariables(result);
    } catch (err: any) {
      console.error("Failed to load script variables:", err);
    }
  };
  
  // Toggle script enabled
  const toggleScript = async (scriptName: string, enabled: boolean) => {
    try {
      if (enabled) {
        await zapClient.enableScript(scriptName);
      } else {
        await zapClient.disableScript(scriptName);
      }
      loadScripts();
    } catch (err: any) {
      setZapError(`Failed to toggle script: ${err.message}`);
    }
  };
  
  // Run standalone script
  const runScript = async (scriptName: string) => {
    setScriptsLoading(true);
    try {
      const result = await zapClient.runScript(scriptName);
      setZapError(null);
      // Show success message
      alert(`Script "${scriptName}" executed successfully!`);
    } catch (err: any) {
      setZapError(`Failed to run script: ${err.message}`);
    } finally {
      setScriptsLoading(false);
    }
  };
  
  // Remove script
  const removeScript = async (scriptName: string) => {
    if (!confirm(`Remove script "${scriptName}"?`)) return;
    try {
      await zapClient.removeScript(scriptName);
      loadScripts();
    } catch (err: any) {
      setZapError(`Failed to remove script: ${err.message}`);
    }
  };
  
  // Set script variable
  const setScriptVar = async () => {
    if (!newScriptVarKey.trim()) return;
    try {
      await zapClient.setScriptVariable(newScriptVarKey, newScriptVarValue);
      setNewScriptVarKey("");
      setNewScriptVarValue("");
      loadScriptVariables();
    } catch (err: any) {
      setZapError(`Failed to set variable: ${err.message}`);
    }
  };
  
  // Clear script variable
  const clearScriptVar = async (key: string) => {
    try {
      await zapClient.clearScriptVariable(key);
      loadScriptVariables();
    } catch (err: any) {
      setZapError(`Failed to clear variable: ${err.message}`);
    }
  };
  
  // Load scripts when expanded
  useEffect(() => {
    if (scriptsExpanded && scripts.length === 0) {
      loadScripts();
      loadScriptEngines();
      loadScriptTypes();
      loadScriptVariables();
    }
  }, [scriptsExpanded]);

  // Export scan report
  const exportZapScan = async (format: "json" | "html") => {
    try {
      const result = await zapClient.getReport(format);
      if (format === "json") {
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `zap-report.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const url = URL.createObjectURL(result);
        const a = document.createElement("a");
        a.href = url;
        a.download = `zap-report.${format}`;
        a.click();
        URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      setZapError(err.message || "Export failed");
    }
  };

  // Export AI Analysis Report
  const [exportingReport, setExportingReport] = useState(false);
  
  const exportAIReport = async (format: "markdown" | "pdf" | "word") => {
    if (!zapAiAnalysis) return;
    
    setExportingReport(true);
    try {
      const targetUrl = zapTargetUrl || zapSelectedScan?.target_url || "Unknown";
      const scanInfo = zapSelectedScan ? {
        scan_type: zapSelectedScan.scan_type,
        completed_at: zapSelectedScan.completed_at,
      } : undefined;
      
      const blob = await zapClient.exportAIReport(zapAiAnalysis, targetUrl, format, scanInfo);
      
      const extension = format === "markdown" ? "md" : format === "pdf" ? "pdf" : "docx";
      const filename = `zap_security_report_${new Date().toISOString().split('T')[0]}.${extension}`;
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setZapError(err.message || "Export failed");
    } finally {
      setExportingReport(false);
    }
  };

  // Auto-save scan when completed
  const autoSaveScan = async (sessionId: string) => {
    try {
      const title = zapScanTitle.trim() 
        ? zapScanTitle.trim()
        : `${new URL(zapTargetUrl).hostname} - ${new Date().toLocaleString()}`;
      await zapClient.saveScan(sessionId, title);
      await loadZapScans();
      setZapScanTitle(""); // Clear title after save
    } catch (err) {
      console.error("Auto-save failed:", err);
    }
  };

  // Helper functions to normalize alert/finding types
  const getAlertRisk = (alert: ZAPAlert | ZAPFinding): string => {
    return 'risk' in alert ? alert.risk : alert.severity;
  };
  
  const getAlertName = (alert: ZAPAlert | ZAPFinding): string => {
    return 'name' in alert ? alert.name : alert.title;
  };
  
  const getAlertUrl = (alert: ZAPAlert | ZAPFinding): string => {
    return 'url' in alert ? alert.url : alert.endpoint;
  };
  
  const getAlertSolution = (alert: ZAPAlert | ZAPFinding): string | undefined => {
    if ('solution' in alert) {
      return alert.solution;
    }
    return (alert as ZAPFinding).recommendation;
  };

  // Filter alerts
  const filteredAlerts = zapAlertFilter === "all" 
    ? zapAlerts 
    : zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === zapAlertFilter);

  // Group alerts by vulnerability type
  const groupedAlerts = filteredAlerts.reduce((acc, alert) => {
    const name = getAlertName(alert);
    if (!acc[name]) {
      acc[name] = [];
    }
    acc[name].push(alert);
    return acc;
  }, {} as Record<string, (ZAPAlert | ZAPFinding)[]>);

  // Get unique affected URLs count
  const uniqueUrls = new Set(zapAlerts.map(a => getAlertUrl(a))).size;

  // Calculate risk statistics
  const riskStats = {
    critical: zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'critical').length,
    high: zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'high').length,
    medium: zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'medium').length,
    low: zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === 'low').length,
    info: zapAlerts.filter(a => ['informational', 'info'].includes(getAlertRisk(a).toLowerCase())).length,
  };

  // AI validate single alert
  const validateAlert = async (alert: ZAPAlert | ZAPFinding, index: number) => {
    const alertId = `alert_${index}`;
    setValidatingAlertId(alertId);
    
    try {
      // Call AI to validate this specific alert
      const alertsForValidation: ZAPAlert[] = [{
        id: alertId,
        name: getAlertName(alert),
        risk: getAlertRisk(alert),
        risk_code: (alert as ZAPAlert).risk_code || 0,
        confidence: (alert as ZAPAlert).confidence || 'Medium',
        url: getAlertUrl(alert),
        description: alert.description || '',
        solution: getAlertSolution(alert) || '',
        cwe_id: alert.cwe_id,
        method: (alert as ZAPAlert).method || 'GET',
        parameter: (alert as ZAPAlert).parameter || (alert as ZAPFinding).parameter,
        attack: (alert as ZAPAlert).attack || (alert as ZAPFinding).payload,
        evidence: (alert as ZAPAlert).evidence || ((alert as ZAPFinding).evidence?.[0]),
      }];
      
      const analysis = await zapClient.aiAnalyze(
        alertsForValidation,
        zapTargetUrl || zapSelectedScan?.target_url || '',
      );
      
      // Parse AI response to determine if false positive
      const isFalsePositive = analysis.summary?.toLowerCase().includes('false positive') || 
                              analysis.summary?.toLowerCase().includes('likely not exploitable');
      
      setAlertValidations(prev => ({
        ...prev,
        [alertId]: {
          validated: true,
          falsePositive: isFalsePositive,
          notes: analysis.summary || 'Validated by AI',
        },
      }));
    } catch (err) {
      console.error('Alert validation failed:', err);
    } finally {
      setValidatingAlertId(null);
    }
  };

  // Risk color helper
  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "high": case "critical": return "#ef4444";
      case "medium": return "#f59e0b";
      case "low": return "#3b82f6";
      case "informational": case "info": return "#6b7280";
      default: return "#6b7280";
    }
  };

  const getRiskBgColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "high": case "critical": return "rgba(239, 68, 68, 0.1)";
      case "medium": return "rgba(245, 158, 11, 0.1)";
      case "low": return "rgba(59, 130, 246, 0.1)";
      case "informational": case "info": return "rgba(107, 114, 128, 0.1)";
      default: return "rgba(107, 114, 128, 0.1)";
    }
  };

  // Guide Panel Component
  const GuidePanel = ({ guideKey, content }: { guideKey: string; content: any }) => (
    <Collapse in={beginnerMode && expandedGuide === guideKey}>
      <Paper
        sx={{
          mt: 1,
          mb: 2,
          p: 2,
          background: "linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(6, 78, 59, 0.2) 100%)",
          border: "1px solid rgba(16, 185, 129, 0.3)",
          borderRadius: 2,
          position: "relative",
          overflow: "hidden",
        }}
      >
        <Box
          sx={{
            position: "absolute",
            top: 0,
            left: 0,
            right: 0,
            height: "3px",
            background: "linear-gradient(90deg, #10b981, #34d399, #10b981)",
            backgroundSize: "200% 100%",
            animation: `${shimmer} 2s linear infinite`,
          }}
        />
        <Typography variant="subtitle2" sx={{ color: "#10b981", fontWeight: 700, mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
          <LightbulbIcon sx={{ fontSize: 18 }} />
          {content.title}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          {content.description}
        </Typography>
        {content.examples && (
          <Box sx={{ mb: 1.5 }}>
            <Typography variant="caption" sx={{ color: "#10b981", fontWeight: 600 }}>Examples:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
              {content.examples.map((ex: any, i: number) => (
                <Chip
                  key={i}
                  label={typeof ex === "string" ? ex : `${ex.value}: ${ex.use}`}
                  size="small"
                  sx={{
                    bgcolor: "rgba(16, 185, 129, 0.15)",
                    color: "#34d399",
                    fontSize: "0.7rem",
                  }}
                />
              ))}
            </Box>
          </Box>
        )}
        {content.tips && (
          <Box>
            <Typography variant="caption" sx={{ color: "#f59e0b", fontWeight: 600 }}>💡 Tips:</Typography>
            <Box component="ul" sx={{ m: 0, pl: 2, "& li": { fontSize: "0.75rem", color: "text.secondary" } }}>
              {content.tips.map((tip: string, i: number) => (
                <li key={i}>{tip}</li>
              ))}
            </Box>
          </Box>
        )}
        {content.options && !content.options.enabled && (
          <Box sx={{ mt: 1 }}>
            {Object.entries(content.options).map(([key, opt]: [string, any]) => (
              <Box key={key} sx={{ mb: 1, p: 1.5, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                <Typography variant="caption" sx={{ color: "#10b981", fontWeight: 600 }}>{opt.name}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ fontSize: "0.75rem" }}>{opt.description}</Typography>
                {opt.bestFor && (
                  <Typography variant="caption" sx={{ color: "#a78bfa" }}>Best for: {opt.bestFor}</Typography>
                )}
                {opt.duration && (
                  <Chip label={`⏱️ ${opt.duration}`} size="small" sx={{ ml: 1, height: 20, fontSize: "0.65rem" }} />
                )}
              </Box>
            ))}
          </Box>
        )}
      </Paper>
    </Collapse>
  );

  return (
    <Box sx={{ 
      p: 3, 
      minHeight: "100vh", 
      background: "linear-gradient(180deg, #0a0a0f 0%, #0f172a 50%, #111827 100%)",
      position: "relative",
      overflow: "hidden",
    }}>
      {/* Animated Background Elements */}
      <Box
        sx={{
          position: "absolute",
          top: "10%",
          left: "5%",
          width: 300,
          height: 300,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(16, 185, 129, 0.1) 0%, transparent 70%)",
          animation: `${pulse} 4s ease-in-out infinite`,
          pointerEvents: "none",
        }}
      />
      <Box
        sx={{
          position: "absolute",
          bottom: "20%",
          right: "10%",
          width: 200,
          height: 200,
          borderRadius: "50%",
          background: "radial-gradient(circle, rgba(139, 92, 246, 0.1) 0%, transparent 70%)",
          animation: `${pulse} 5s ease-in-out infinite`,
          animationDelay: "1s",
          pointerEvents: "none",
        }}
      />
      
      {/* Floating Radar Icon */}
      <Box
        sx={{
          position: "absolute",
          top: "15%",
          right: "15%",
          opacity: 0.05,
          animation: `${float} 6s ease-in-out infinite`,
          pointerEvents: "none",
        }}
      >
        <RadarIcon sx={{ fontSize: 200, color: "#10b981" }} />
      </Box>

      {/* Header with back button */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 3, position: "relative", zIndex: 1 }}>
        <IconButton 
          component={Link} 
          to="/dynamic/fuzzer" 
          sx={{ 
            bgcolor: "rgba(16, 185, 129, 0.1)", 
            "&:hover": { bgcolor: "rgba(16, 185, 129, 0.2)", transform: "scale(1.1)" },
            transition: "all 0.3s ease",
          }}
        >
          <ArrowBackIcon sx={{ color: "#10b981" }} />
        </IconButton>
        <Box sx={{ flex: 1 }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
            {/* Animated Logo */}
            <Box
              sx={{
                position: "relative",
                width: 50,
                height: 50,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Box
                sx={{
                  position: "absolute",
                  width: "100%",
                  height: "100%",
                  border: "2px solid rgba(16, 185, 129, 0.3)",
                  borderRadius: "50%",
                  borderTopColor: "#10b981",
                  animation: `${radarSweep} 2s linear infinite`,
                }}
              />
              <GpsFixedIcon sx={{ fontSize: 28, color: "#10b981", zIndex: 1 }} />
            </Box>
            <Box>
              <Typography 
                variant="h4" 
                sx={{ 
                  fontWeight: 800,
                  background: "linear-gradient(135deg, #10b981 0%, #34d399 50%, #6ee7b7 100%)",
                  backgroundClip: "text",
                  WebkitBackgroundClip: "text",
                  WebkitTextFillColor: "transparent",
                  textShadow: "0 0 40px rgba(16, 185, 129, 0.3)",
                  letterSpacing: "-0.5px",
                }}
              >
                OWASP ZAP Scanner
              </Typography>
              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                Dynamic Application Security Testing (DAST) • Spider • Active Scan • AJAX Spider
              </Typography>
            </Box>
          </Box>
        </Box>
        
        {/* Beginner Mode Toggle */}
        <Tooltip title="Toggle Beginner's Guide Mode - Get helpful explanations for each field" arrow>
          <Button
            variant={beginnerMode ? "contained" : "outlined"}
            startIcon={<SchoolIcon />}
            onClick={() => setBeginnerMode(!beginnerMode)}
            sx={{
              borderColor: "#f59e0b",
              color: beginnerMode ? "#000" : "#f59e0b",
              bgcolor: beginnerMode ? "#f59e0b" : "transparent",
              "&:hover": { 
                bgcolor: beginnerMode ? "#d97706" : "rgba(245, 158, 11, 0.1)",
                borderColor: "#f59e0b",
              },
              animation: beginnerMode ? `${pulse} 2s ease-in-out infinite` : "none",
            }}
          >
            {beginnerMode ? "Guide ON" : "Guide Mode"}
          </Button>
        </Tooltip>
        
        <Chip
          icon={zapHealthy ? <CheckCircleIcon /> : <ErrorIcon />}
          label={zapHealthy === null ? "Checking..." : zapHealthy ? "ZAP Online" : "ZAP Offline"}
          sx={{
            bgcolor: zapHealthy ? "rgba(16, 185, 129, 0.2)" : "rgba(239, 68, 68, 0.2)",
            color: zapHealthy ? "#10b981" : "#ef4444",
            border: `1px solid ${zapHealthy ? "#10b981" : "#ef4444"}`,
            fontWeight: 600,
            animation: zapHealthy ? `${glow} 2s ease-in-out infinite` : "none",
          }}
        />
      </Box>

      {/* Beginner Mode Welcome Banner */}
      <Collapse in={beginnerMode}>
        <Paper
          sx={{
            p: 3,
            mb: 3,
            background: "linear-gradient(135deg, rgba(245, 158, 11, 0.1) 0%, rgba(217, 119, 6, 0.05) 100%)",
            border: "1px solid rgba(245, 158, 11, 0.3)",
            borderRadius: 3,
            position: "relative",
            overflow: "hidden",
          }}
        >
          <Box
            sx={{
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              height: "4px",
              background: "linear-gradient(90deg, #f59e0b, #fbbf24, #f59e0b)",
              backgroundSize: "200% 100%",
              animation: `${shimmer} 2s linear infinite`,
            }}
          />
          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 2 }}>
            <Box
              sx={{
                p: 1.5,
                bgcolor: "rgba(245, 158, 11, 0.2)",
                borderRadius: 2,
                animation: `${float} 3s ease-in-out infinite`,
              }}
            >
              <SchoolIcon sx={{ fontSize: 32, color: "#f59e0b" }} />
            </Box>
            <Box sx={{ flex: 1 }}>
              <Typography variant="h6" sx={{ color: "#fbbf24", fontWeight: 700, mb: 0.5 }}>
                🎓 Beginner's Guide Mode Active
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Click the <InfoIcon sx={{ fontSize: 14, verticalAlign: "middle", mx: 0.5 }} /> icons next to each field to learn what it does. 
                Each setting has examples and tips to help you configure the perfect scan!
              </Typography>
              <Box sx={{ display: "flex", gap: 2, mt: 2 }}>
                <Chip icon={<SpeedIcon />} label="Fast Scan: Spider Only" size="small" sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#60a5fa" }} />
                <Chip icon={<SecurityIcon />} label="Full Security: Full Scan" size="small" sx={{ bgcolor: "rgba(239, 68, 68, 0.2)", color: "#f87171" }} />
                <Chip icon={<AccountTreeIcon />} label="JS Apps: AJAX Spider" size="small" sx={{ bgcolor: "rgba(139, 92, 246, 0.2)", color: "#a78bfa" }} />
              </Box>
            </Box>
          </Box>
        </Paper>
      </Collapse>

      {zapError && (
        <Alert severity="error" onClose={() => setZapError(null)} sx={{ mb: 3 }}>
          {zapError}
        </Alert>
      )}

      {/* Main Content */}
      <Grid container spacing={3} sx={{ position: "relative", zIndex: 1 }}>
        {/* Top Row - Configuration and Saved Scans side by side */}
        {/* Left Panel - Configuration */}
        <Grid item xs={12} md={7}>
          <Paper 
            sx={{ 
              p: 3, 
              borderRadius: 3, 
              bgcolor: "rgba(17, 24, 39, 0.9)", 
              border: "1px solid rgba(16, 185, 129, 0.2)",
              backdropFilter: "blur(10px)",
              transition: "all 0.3s ease",
              height: "100%",
              "&:hover": {
                border: "1px solid rgba(16, 185, 129, 0.4)",
                boxShadow: "0 0 30px rgba(16, 185, 129, 0.1)",
              },
            }}
          >
            <Typography variant="h6" fontWeight={600} sx={{ mb: 3, display: "flex", alignItems: "center", gap: 1, color: "#10b981" }}>
              <SettingsIcon sx={{ animation: zapIsRunning ? `${radarSweep} 2s linear infinite` : "none" }} />
              Scan Configuration
            </Typography>

            <Grid container spacing={2}>
              {/* Target URL Field */}
              <Grid item xs={12}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <TextField
                    fullWidth
                    label="Target URL"
                    value={zapTargetUrl}
                    onChange={(e) => setZapTargetUrl(e.target.value)}
                    placeholder="http://host.docker.internal:8080 or http://192.168.x.x"
                    disabled={zapIsRunning}
                    InputProps={{
                      startAdornment: <HttpIcon sx={{ mr: 1, color: "text.secondary" }} />,
                    }}
                    helperText={needsInternalConversion(zapTargetUrl) ? 
                      "💡 Tip: localhost detected. Click 'Convert' to use host.docker.internal for internal scanning." : 
                      undefined
                    }
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        "&:hover fieldset": { borderColor: "#10b981" },
                        "&.Mui-focused fieldset": { borderColor: "#10b981" },
                        transition: "all 0.3s ease",
                      },
                    }}
                  />
                  {needsInternalConversion(zapTargetUrl) && (
                    <Button
                      size="small"
                      variant="outlined"
                      onClick={() => setZapTargetUrl(convertToInternalUrl(zapTargetUrl))}
                      disabled={zapIsRunning}
                      sx={{ 
                        minWidth: 80,
                        borderColor: "#f59e0b",
                        color: "#f59e0b",
                        "&:hover": { borderColor: "#d97706", bgcolor: "rgba(245, 158, 11, 0.1)" }
                      }}
                    >
                      Convert
                    </Button>
                  )}
                  {beginnerMode && (
                    <IconButton 
                      size="small" 
                      onClick={() => setExpandedGuide(expandedGuide === "targetUrl" ? null : "targetUrl")}
                      sx={{ 
                        color: expandedGuide === "targetUrl" ? "#10b981" : "text.secondary",
                        bgcolor: expandedGuide === "targetUrl" ? "rgba(16, 185, 129, 0.1)" : "transparent",
                      }}
                    >
                      <HelpOutlineIcon />
                    </IconButton>
                  )}
                </Box>
                <GuidePanel guideKey="targetUrl" content={GUIDE_CONTENT.targetUrl} />
              </Grid>

              {/* Scan Title Field */}
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Scan Name (Optional)"
                  value={zapScanTitle}
                  onChange={(e) => {
                    setZapScanTitle(e.target.value);
                    zapScanTitleRef.current = e.target.value;
                  }}
                  placeholder="e.g., Production API Security Scan"
                  disabled={zapIsRunning}
                  size="small"
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      "&:hover fieldset": { borderColor: "#10b981" },
                      "&.Mui-focused fieldset": { borderColor: "#10b981" },
                    },
                  }}
                />
              </Grid>

              {/* Scan Type Field */}
              <Grid item xs={12}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <FormControl fullWidth>
                    <InputLabel>Scan Type</InputLabel>
                    <Select
                      value={zapScanType}
                      onChange={(e) => setZapScanType(e.target.value as any)}
                      disabled={zapIsRunning}
                      label="Scan Type"
                      sx={{
                        "& .MuiOutlinedInput-notchedOutline": {
                          transition: "all 0.3s ease",
                        },
                        "&:hover .MuiOutlinedInput-notchedOutline": {
                          borderColor: "#10b981",
                        },
                      }}
                    >
                      <MenuItem value="spider">🕷️ Spider Only - Fast crawl</MenuItem>
                      <MenuItem value="ajax_spider">⚡ AJAX Spider - JavaScript apps</MenuItem>
                      <MenuItem value="active_scan">🎯 Active Scan - Attack testing</MenuItem>
                      <MenuItem value="full_scan">🔥 Full Scan - Spider + Active</MenuItem>
                    </Select>
                  </FormControl>
                  {beginnerMode && (
                    <IconButton 
                      size="small" 
                      onClick={() => setExpandedGuide(expandedGuide === "scanType" ? null : "scanType")}
                      sx={{ 
                        color: expandedGuide === "scanType" ? "#10b981" : "text.secondary",
                        bgcolor: expandedGuide === "scanType" ? "rgba(16, 185, 129, 0.1)" : "transparent",
                      }}
                    >
                      <HelpOutlineIcon />
                    </IconButton>
                  )}
                </Box>
                <GuidePanel guideKey="scanType" content={GUIDE_CONTENT.scanType} />
              </Grid>

              {/* Max Depth Field */}
              <Grid item xs={6}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <TextField
                    fullWidth
                    type="number"
                    label="Max Depth"
                    value={zapMaxDepth}
                    onChange={(e) => setZapMaxDepth(parseInt(e.target.value) || 5)}
                    disabled={zapIsRunning}
                    inputProps={{ min: 1, max: 20 }}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        "&:hover fieldset": { borderColor: "#10b981" },
                        "&.Mui-focused fieldset": { borderColor: "#10b981" },
                      },
                    }}
                  />
                  {beginnerMode && (
                    <IconButton 
                      size="small" 
                      onClick={() => setExpandedGuide(expandedGuide === "maxDepth" ? null : "maxDepth")}
                      sx={{ 
                        color: expandedGuide === "maxDepth" ? "#10b981" : "text.secondary",
                        bgcolor: expandedGuide === "maxDepth" ? "rgba(16, 185, 129, 0.1)" : "transparent",
                      }}
                    >
                      <HelpOutlineIcon />
                    </IconButton>
                  )}
                </Box>
              </Grid>

              {/* Recurse Toggle */}
              <Grid item xs={6}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={zapRecurse}
                        onChange={(e) => setZapRecurse(e.target.checked)}
                        disabled={zapIsRunning}
                        sx={{
                          "& .MuiSwitch-switchBase.Mui-checked": { color: "#10b981" },
                          "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { backgroundColor: "#10b981" },
                        }}
                      />
                    }
                    label="Recurse"
                  />
                  {beginnerMode && (
                    <IconButton 
                      size="small" 
                      onClick={() => setExpandedGuide(expandedGuide === "recurse" ? null : "recurse")}
                      sx={{ 
                        color: expandedGuide === "recurse" ? "#10b981" : "text.secondary",
                        bgcolor: expandedGuide === "recurse" ? "rgba(16, 185, 129, 0.1)" : "transparent",
                      }}
                    >
                      <HelpOutlineIcon />
                    </IconButton>
                  )}
                </Box>
              </Grid>

              {/* Guide Panels for Max Depth and Recurse */}
              <Grid item xs={12}>
                <GuidePanel guideKey="maxDepth" content={GUIDE_CONTENT.maxDepth} />
                <GuidePanel guideKey="recurse" content={GUIDE_CONTENT.recurse} />
              </Grid>

              {/* AI Context Input */}
              <Grid item xs={12}>
                <Paper
                  sx={{
                    p: 2,
                    bgcolor: "rgba(139, 92, 246, 0.05)",
                    border: "1px solid rgba(139, 92, 246, 0.2)",
                    borderRadius: 2,
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1.5 }}>
                    <PsychologyIcon sx={{ color: "#a78bfa", fontSize: 20 }} />
                    <Typography variant="subtitle2" sx={{ color: "#a78bfa", fontWeight: 600 }}>
                      AI Context (Optional)
                    </Typography>
                    <Tooltip title="Provide additional context about the target to help AI generate more relevant analysis. Examples: application type, tech stack, known sensitive endpoints, business context, etc.">
                      <HelpOutlineIcon sx={{ fontSize: 16, color: "rgba(255,255,255,0.4)", cursor: "help" }} />
                    </Tooltip>
                  </Box>
                  <TextField
                    fullWidth
                    multiline
                    rows={3}
                    value={aiContext}
                    onChange={(e) => setAiContext(e.target.value)}
                    placeholder="e.g., This is an e-commerce application built with React/Node.js. Focus on payment-related vulnerabilities and authentication bypasses. The /api/admin/* endpoints are particularly sensitive..."
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        bgcolor: "rgba(0,0,0,0.2)",
                        fontSize: "0.9rem",
                        "& fieldset": { borderColor: "rgba(139, 92, 246, 0.3)" },
                        "&:hover fieldset": { borderColor: "rgba(139, 92, 246, 0.5)" },
                        "&.Mui-focused fieldset": { borderColor: "#a78bfa" },
                      },
                      "& .MuiInputBase-input": { color: "rgba(255,255,255,0.9)" },
                      "& .MuiInputBase-input::placeholder": { color: "rgba(255,255,255,0.4)" },
                    }}
                  />
                  <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.4)", mt: 1, display: "block" }}>
                    💡 This context will be used by AI when analyzing scan results
                  </Typography>
                </Paper>
              </Grid>

              <Grid item xs={12}>
                <Box sx={{ display: "flex", gap: 2 }}>
                  <Button
                    fullWidth
                    variant="contained"
                    startIcon={zapIsRunning ? <StopIcon /> : <PlayArrowIcon />}
                    onClick={zapIsRunning ? stopZapScan : startZapScan}
                    disabled={!zapTargetUrl || !zapHealthy}
                    sx={{
                      py: 1.5,
                      fontSize: "1rem",
                      fontWeight: 700,
                      bgcolor: zapIsRunning ? "#ef4444" : "#10b981",
                      "&:hover": { 
                        bgcolor: zapIsRunning ? "#dc2626" : "#059669",
                        transform: "translateY(-2px)",
                        boxShadow: zapIsRunning 
                          ? "0 10px 30px rgba(239, 68, 68, 0.3)" 
                          : "0 10px 30px rgba(16, 185, 129, 0.3)",
                      },
                      transition: "all 0.3s ease",
                      animation: zapIsRunning ? `${pulse} 1.5s ease-in-out infinite` : "none",
                    }}
                  >
                    {zapIsRunning ? "⏹️ Stop Scan" : "🚀 Start Scan"}
                  </Button>
                </Box>
              </Grid>
            </Grid>

            {/* Progress */}
            {zapProgress && (
              <Box 
                sx={{ 
                  mt: 3, 
                  p: 2, 
                  bgcolor: "rgba(16, 185, 129, 0.05)", 
                  borderRadius: 2,
                  border: "1px solid rgba(16, 185, 129, 0.2)",
                  position: "relative",
                  overflow: "hidden",
                }}
              >
                {/* Scanning Line Animation */}
                {zapIsRunning && (
                  <Box
                    sx={{
                      position: "absolute",
                      left: 0,
                      right: 0,
                      height: "2px",
                      background: "linear-gradient(90deg, transparent, #10b981, transparent)",
                      animation: `${scanLine} 2s linear infinite`,
                    }}
                  />
                )}
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <RadarIcon sx={{ color: "#10b981", fontSize: 20, animation: zapIsRunning ? `${radarSweep} 1s linear infinite` : "none" }} />
                  <Typography variant="body2" sx={{ color: "#10b981", fontWeight: 600 }}>
                    {zapProgress.phase || "Scanning"}
                  </Typography>
                  <Chip 
                    label={zapProgress.message || zapProgress.type} 
                    size="small" 
                    sx={{ 
                      bgcolor: "rgba(16, 185, 129, 0.2)", 
                      color: "#34d399",
                      height: 20,
                      fontSize: "0.7rem",
                    }} 
                  />
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={zapOverallProgress} 
                  sx={{ 
                    height: 10, 
                    borderRadius: 5,
                    bgcolor: "rgba(16, 185, 129, 0.1)",
                    "& .MuiLinearProgress-bar": { 
                      bgcolor: "#10b981",
                      borderRadius: 5,
                      background: "linear-gradient(90deg, #10b981, #34d399, #10b981)",
                      backgroundSize: "200% 100%",
                      animation: `${shimmer} 1.5s linear infinite`,
                    },
                  }} 
                />
                <Box sx={{ display: "flex", justifyContent: "space-between", mt: 1 }}>
                  <Typography variant="caption" sx={{ color: "#34d399" }}>
                    🌐 URLs: {zapProgress.urls_found || 0}
                  </Typography>
                  <Typography variant="caption" sx={{ color: "#34d399", fontWeight: 700 }}>
                    {zapOverallProgress}%
                  </Typography>
                </Box>
              </Box>
            )}

            {/* Quick Stats */}
            {zapAlerts.length > 0 && (
              <Box 
                sx={{ 
                  mt: 3, 
                  p: 2, 
                  bgcolor: "rgba(239, 68, 68, 0.05)", 
                  borderRadius: 2,
                  border: "1px solid rgba(239, 68, 68, 0.2)",
                }}
              >
                <Typography variant="subtitle2" sx={{ mb: 2, color: "#f87171", display: "flex", alignItems: "center", gap: 1 }}>
                  <BugReportIcon sx={{ fontSize: 18 }} />
                  Alert Summary
                </Typography>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  {["High", "Medium", "Low", "Informational"].map(risk => {
                    const count = zapAlerts.filter(a => getAlertRisk(a).toLowerCase() === risk.toLowerCase()).length;
                    if (count === 0) return null;
                    return (
                      <Chip
                        key={risk}
                        label={`${risk}: ${count}`}
                        size="small"
                        sx={{
                          bgcolor: getRiskBgColor(risk),
                          color: getRiskColor(risk),
                          border: `1px solid ${getRiskColor(risk)}`,
                          fontWeight: 600,
                          animation: risk === "High" && count > 0 ? `${pulse} 2s ease-in-out infinite` : "none",
                        }}
                      />
                    );
                  })}
                </Box>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Right Panel - Saved Scans */}
        <Grid item xs={12} md={5}>
          <Paper 
            sx={{ 
              p: 3, 
              borderRadius: 3, 
              bgcolor: "rgba(17, 24, 39, 0.9)", 
              border: "1px solid rgba(16, 185, 129, 0.2)",
              backdropFilter: "blur(10px)",
              transition: "all 0.3s ease",
              height: "100%",
              "&:hover": {
                border: "1px solid rgba(16, 185, 129, 0.4)",
                boxShadow: "0 0 30px rgba(16, 185, 129, 0.1)",
              },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h6" fontWeight={600} sx={{ display: "flex", alignItems: "center", gap: 1, color: "#10b981" }}>
                <AssessmentIcon />
                Saved Scans
              </Typography>
              <IconButton size="small" onClick={loadZapScans} disabled={zapLoading}>
                <RefreshIcon sx={{ color: "#10b981" }} />
              </IconButton>
            </Box>
            
            {zapScans.length === 0 ? (
              <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                No saved scans yet. Run a scan to get started.
              </Typography>
            ) : (
              <List sx={{ maxHeight: 350, overflow: "auto" }}>
                {zapScans.map(scan => (
                  <ListItem
                    key={scan.id}
                    sx={{
                      bgcolor: zapSelectedScan?.id === scan.id ? "rgba(16, 185, 129, 0.1)" : "transparent",
                      borderRadius: 2,
                      mb: 1,
                      border: zapSelectedScan?.id === scan.id ? "1px solid rgba(16, 185, 129, 0.3)" : "1px solid transparent",
                      cursor: "pointer",
                      "&:hover": { bgcolor: "rgba(16, 185, 129, 0.05)" },
                    }}
                    onClick={() => viewZapScanDetails(scan.id)}
                    secondaryAction={
                      <Box>
                        <IconButton size="small" onClick={(e) => { e.stopPropagation(); viewZapScanDetails(scan.id); }}>
                          <VisibilityIcon sx={{ fontSize: 18 }} />
                        </IconButton>
                        <IconButton size="small" onClick={(e) => { e.stopPropagation(); deleteZapScan(scan.id); }}>
                          <DeleteIcon sx={{ fontSize: 18, color: "#ef4444" }} />
                        </IconButton>
                      </Box>
                    }
                  >
                    <ListItemText
                      primary={
                        <Typography variant="body2" sx={{ color: "#fff", fontWeight: 500 }}>
                          {/* Show custom title, or extract a better name from the default format */}
                          {scan.title && !scan.title.startsWith("ZAP Scan:") 
                            ? scan.title 
                            : (() => {
                                try {
                                  return new URL(scan.target_url).hostname;
                                } catch {
                                  return scan.title || "Unknown Scan";
                                }
                              })()
                          }
                        </Typography>
                      }
                      secondary={
                        <Box>
                          <Typography variant="caption" color="text.secondary" display="block">
                            {scan.target_url}
                          </Typography>
                          <Typography variant="caption" sx={{ color: 'rgba(16, 185, 129, 0.7)' }}>
                            {scan.created_at ? new Date(scan.created_at).toLocaleString('en-US', { 
                              month: 'short', 
                              day: 'numeric', 
                              hour: '2-digit',
                              minute: '2-digit'
                            }) : 'N/A'} • {scan.alerts?.total || 0} alerts • {scan.scan_type || 'full_scan'}
                          </Typography>
                        </Box>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            )}
          </Paper>
        </Grid>

        {/* WebSocket and GraphQL Testing Row */}
        <Grid item xs={12} md={6}>
          <Accordion 
            expanded={wsExpanded}
            onChange={() => setWsExpanded(!wsExpanded)}
            sx={{
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(59, 130, 246, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&.Mui-expanded": {
                margin: 0,
                border: "1px solid rgba(59, 130, 246, 0.5)",
              },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ color: "#60a5fa" }} />}
              sx={{
                "& .MuiAccordionSummary-content": { alignItems: "center", gap: 2 },
              }}
            >
              <CableIcon sx={{ color: "#60a5fa" }} />
              <Typography variant="h6" sx={{ color: "#60a5fa", fontWeight: 600 }}>
                WebSocket Testing
              </Typography>
              {wsChannels.length > 0 && (
                <Chip 
                  label={`${wsChannels.length} channels`} 
                  size="small" 
                  sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#60a5fa", ml: 1 }} 
                />
              )}
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Monitor and interact with WebSocket connections discovered during scanning.
                  Send custom messages to test for injection vulnerabilities and message manipulation.
                </Typography>

                {wsLoading ? (
                  <Box sx={{ display: "flex", justifyContent: "center", py: 3 }}>
                    <CircularProgress size={32} sx={{ color: "#60a5fa" }} />
                  </Box>
                ) : wsChannels.length === 0 ? (
                  <Alert severity="info" sx={{ bgcolor: "rgba(59, 130, 246, 0.1)" }}>
                    No WebSocket channels discovered yet. Run a spider or active scan on a target that uses WebSocket connections.
                  </Alert>
                ) : (
                  <>
                    {/* Channel Selector */}
                    <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                      <InputLabel sx={{ color: "rgba(255,255,255,0.7)" }}>Select Channel</InputLabel>
                      <Select
                        value={wsSelectedChannel || ""}
                        onChange={(e) => setWsSelectedChannel(e.target.value as number)}
                        label="Select Channel"
                        sx={{
                          "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(59, 130, 246, 0.3)" },
                          "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(59, 130, 246, 0.5)" },
                        }}
                      >
                        {wsChannels.map((channel) => (
                          <MenuItem key={channel.id} value={channel.id}>
                            {channel.url || `${channel.host}:${channel.port}`}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>

                    {/* Messages List */}
                    <Paper sx={{ maxHeight: 200, overflow: "auto", bgcolor: "rgba(0,0,0,0.3)", p: 1, mb: 2 }}>
                      {wsMessages.length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                          No messages in this channel
                        </Typography>
                      ) : (
                        wsMessages.map((msg) => (
                          <Box 
                            key={msg.id} 
                            sx={{ 
                              p: 1, 
                              mb: 0.5, 
                              bgcolor: msg.isOutgoing ? "rgba(59, 130, 246, 0.1)" : "rgba(16, 185, 129, 0.1)",
                              borderRadius: 1,
                              borderLeft: `3px solid ${msg.isOutgoing ? "#60a5fa" : "#10b981"}`,
                            }}
                          >
                            <Typography variant="caption" sx={{ color: msg.isOutgoing ? "#60a5fa" : "#10b981" }}>
                              {msg.isOutgoing ? "⬆ OUT" : "⬇ IN"} • {msg.readableOpcode} • {msg.payloadLength} bytes
                            </Typography>
                            <Typography variant="body2" sx={{ color: "#fff", fontFamily: "monospace", fontSize: "0.75rem", mt: 0.5 }}>
                              {msg.payload?.substring(0, 200) || "(no payload)"}
                              {(msg.payload?.length || 0) > 200 && "..."}
                            </Typography>
                          </Box>
                        ))
                      )}
                    </Paper>

                    {/* Send Message */}
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <TextField
                        fullWidth
                        size="small"
                        placeholder="Send WebSocket message..."
                        value={wsSendMessage}
                        onChange={(e) => setWsSendMessage(e.target.value)}
                        onKeyDown={(e) => e.key === "Enter" && sendWsMessage()}
                        sx={{
                          "& .MuiOutlinedInput-root": {
                            "&:hover fieldset": { borderColor: "#60a5fa" },
                          },
                        }}
                      />
                      <Button 
                        variant="contained" 
                        onClick={sendWsMessage}
                        disabled={!wsSendMessage.trim() || wsSelectedChannel === null}
                        sx={{ bgcolor: "#3b82f6", "&:hover": { bgcolor: "#2563eb" } }}
                      >
                        <SendIcon />
                      </Button>
                      <IconButton onClick={loadWsMessages} size="small" sx={{ color: "#60a5fa" }}>
                        <RefreshIcon />
                      </IconButton>
                    </Box>
                  </>
                )}
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        <Grid item xs={12} md={6}>
          <Accordion 
            expanded={gqlExpanded}
            onChange={() => setGqlExpanded(!gqlExpanded)}
            sx={{
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(236, 72, 153, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&.Mui-expanded": {
                margin: 0,
                border: "1px solid rgba(236, 72, 153, 0.5)",
              },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ color: "#f472b6" }} />}
              sx={{
                "& .MuiAccordionSummary-content": { alignItems: "center", gap: 2 },
              }}
            >
              <HubIcon sx={{ color: "#f472b6" }} />
              <Typography variant="h6" sx={{ color: "#f472b6", fontWeight: 600 }}>
                GraphQL Testing
              </Typography>
              {gqlOptions && (
                <Chip 
                  label={gqlOptions.request_method} 
                  size="small" 
                  sx={{ bgcolor: "rgba(236, 72, 153, 0.2)", color: "#f472b6", ml: 1 }} 
                />
              )}
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Import GraphQL schemas via introspection or SDL for comprehensive API security testing.
                  ZAP will automatically generate queries to test for injection and authorization vulnerabilities.
                </Typography>

                {/* Import Methods */}
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12}>
                    <TextField
                      fullWidth
                      size="small"
                      label="GraphQL Endpoint URL"
                      placeholder="http://target.com/graphql"
                      value={gqlEndpointUrl}
                      onChange={(e) => setGqlEndpointUrl(e.target.value)}
                      sx={{
                        "& .MuiOutlinedInput-root": {
                          "&:hover fieldset": { borderColor: "#ec4899" },
                        },
                      }}
                    />
                  </Grid>
                </Grid>

                <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={importGqlUrl}
                    disabled={gqlLoading || !gqlEndpointUrl.trim()}
                    startIcon={gqlLoading ? <CircularProgress size={16} /> : <RadarIcon />}
                    sx={{ 
                      borderColor: "#ec4899", 
                      color: "#f472b6",
                      "&:hover": { borderColor: "#db2777", bgcolor: "rgba(236, 72, 153, 0.1)" }
                    }}
                  >
                    Import via Introspection
                  </Button>
                </Box>

                {/* Schema Import (SDL) */}
                <Accordion 
                  sx={{ 
                    bgcolor: "rgba(0,0,0,0.2)", 
                    mb: 2,
                    "&:before": { display: "none" },
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#f472b6" }} />}>
                    <Typography variant="body2" sx={{ color: "#f472b6" }}>
                      Or import GraphQL SDL manually
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TextField
                      fullWidth
                      multiline
                      rows={4}
                      size="small"
                      placeholder={`type Query {\n  users: [User!]!\n  user(id: ID!): User\n}\n\ntype User {\n  id: ID!\n  name: String!\n}`}
                      value={gqlSchemaContent}
                      onChange={(e) => setGqlSchemaContent(e.target.value)}
                      sx={{
                        mb: 1,
                        "& .MuiOutlinedInput-root": {
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          "&:hover fieldset": { borderColor: "#ec4899" },
                        },
                      }}
                    />
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={importGqlSchema}
                      disabled={gqlLoading || !gqlSchemaContent.trim() || !gqlEndpointUrl.trim()}
                      sx={{ 
                        borderColor: "#ec4899", 
                        color: "#f472b6",
                        "&:hover": { borderColor: "#db2777", bgcolor: "rgba(236, 72, 153, 0.1)" }
                      }}
                    >
                      Import SDL Schema
                    </Button>
                  </AccordionDetails>
                </Accordion>

                {/* Status Message */}
                {gqlImportStatus && (
                  <Alert 
                    severity={gqlImportStatus.startsWith("✅") ? "success" : "error"}
                    sx={{ mb: 2, bgcolor: gqlImportStatus.startsWith("✅") ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)" }}
                  >
                    {gqlImportStatus}
                  </Alert>
                )}

                {/* Current Options */}
                {gqlOptions && (
                  <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)" }}>
                    <Typography variant="subtitle2" sx={{ color: "#f472b6", mb: 1 }}>
                      Current Configuration
                    </Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Request Method</Typography>
                        <Typography variant="body2" sx={{ color: "#fff" }}>{gqlOptions.request_method}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Query Split</Typography>
                        <Typography variant="body2" sx={{ color: "#fff" }}>{gqlOptions.query_split_type}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Max Query Depth</Typography>
                        <Typography variant="body2" sx={{ color: "#fff" }}>{gqlOptions.max_query_depth}</Typography>
                      </Grid>
                      <Grid item xs={6}>
                        <Typography variant="caption" color="text.secondary">Max Args Depth</Typography>
                        <Typography variant="body2" sx={{ color: "#fff" }}>{gqlOptions.max_args_depth}</Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                )}
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Manual Request Editor Panel */}
        <Grid item xs={12} md={6}>
          <Accordion 
            expanded={reqEditorExpanded}
            onChange={() => setReqEditorExpanded(!reqEditorExpanded)}
            sx={{
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(245, 158, 11, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&.Mui-expanded": {
                margin: 0,
                border: "1px solid rgba(245, 158, 11, 0.5)",
              },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ color: "#fbbf24" }} />}
              sx={{
                "& .MuiAccordionSummary-content": { alignItems: "center", gap: 2 },
              }}
            >
              <EditNoteIcon sx={{ color: "#fbbf24" }} />
              <Typography variant="h6" sx={{ color: "#fbbf24", fontWeight: 600 }}>
                Manual Request Editor
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Craft and send custom HTTP requests through ZAP for manual testing.
                  Useful for testing specific endpoints, authentication flows, or custom payloads.
                </Typography>

                {/* Request Editor */}
                <TextField
                  fullWidth
                  multiline
                  rows={8}
                  placeholder={`GET /api/users HTTP/1.1\nHost: example.com\nAuthorization: Bearer token\nContent-Type: application/json\n\n{"key": "value"}`}
                  value={reqEditorContent}
                  onChange={(e) => setReqEditorContent(e.target.value)}
                  sx={{
                    mb: 2,
                    "& .MuiOutlinedInput-root": {
                      fontFamily: "monospace",
                      fontSize: "0.8rem",
                      bgcolor: "rgba(0,0,0,0.3)",
                      "&:hover fieldset": { borderColor: "#f59e0b" },
                      "&.Mui-focused fieldset": { borderColor: "#f59e0b" },
                    },
                  }}
                />

                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <FormControlLabel
                    control={
                      <Switch 
                        checked={reqEditorFollowRedirects}
                        onChange={(e) => setReqEditorFollowRedirects(e.target.checked)}
                        sx={{ "& .Mui-checked": { color: "#f59e0b" } }}
                      />
                    }
                    label="Follow Redirects"
                    sx={{ color: "rgba(255,255,255,0.7)" }}
                  />
                  <Button
                    variant="contained"
                    onClick={sendManualRequest}
                    disabled={reqEditorLoading || !reqEditorContent.trim()}
                    startIcon={reqEditorLoading ? <CircularProgress size={16} /> : <SendIcon />}
                    sx={{ bgcolor: "#f59e0b", "&:hover": { bgcolor: "#d97706" } }}
                  >
                    Send Request
                  </Button>
                </Box>

                {/* Response */}
                {reqEditorResponse && (
                  <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.3)", maxHeight: 200, overflow: "auto" }}>
                    <Typography variant="subtitle2" sx={{ color: "#fbbf24", mb: 1 }}>Response</Typography>
                    <Typography 
                      variant="body2" 
                      component="pre"
                      sx={{ 
                        fontFamily: "monospace", 
                        fontSize: "0.75rem", 
                        color: "#fff",
                        whiteSpace: "pre-wrap",
                        wordBreak: "break-all",
                      }}
                    >
                      {reqEditorResponse}
                    </Typography>
                  </Paper>
                )}

                {/* Recent History */}
                {reqHistory.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" sx={{ color: "#fbbf24", mb: 1 }}>Recent Requests</Typography>
                    <List dense sx={{ maxHeight: 150, overflow: "auto", bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                      {reqHistory.slice(0, 10).map((msg) => (
                        <ListItem key={msg.id} sx={{ py: 0.5 }}>
                          <ListItemText
                            primary={
                              <Typography variant="caption" sx={{ color: "#fff", fontFamily: "monospace" }}>
                                {msg.method} {msg.url?.substring(0, 50)}{(msg.url?.length || 0) > 50 ? "..." : ""}
                              </Typography>
                            }
                            secondary={
                              <Typography variant="caption" color="text.secondary">
                                {msg.statusCode} • {msg.rtt}ms
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </Box>
                )}
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* OpenAPI/Swagger Import Panel */}
        <Grid item xs={12} md={6}>
          <Accordion 
            expanded={openApiExpanded}
            onChange={() => setOpenApiExpanded(!openApiExpanded)}
            sx={{
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(34, 197, 94, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&.Mui-expanded": {
                margin: 0,
                border: "1px solid rgba(34, 197, 94, 0.5)",
              },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ color: "#4ade80" }} />}
              sx={{
                "& .MuiAccordionSummary-content": { alignItems: "center", gap: 2 },
              }}
            >
              <ApiIcon sx={{ color: "#4ade80" }} />
              <Typography variant="h6" sx={{ color: "#4ade80", fontWeight: 600 }}>
                OpenAPI / Swagger Import
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Import OpenAPI (v3) or Swagger (v2) API definitions for comprehensive endpoint discovery and testing.
                  ZAP will automatically identify all endpoints and parameters for security scanning.
                </Typography>

                {/* URL Import */}
                <TextField
                  fullWidth
                  size="small"
                  label="OpenAPI/Swagger URL"
                  placeholder="https://api.example.com/openapi.json or /swagger.yaml"
                  value={openApiUrl}
                  onChange={(e) => setOpenApiUrl(e.target.value)}
                  sx={{
                    mb: 2,
                    "& .MuiOutlinedInput-root": {
                      "&:hover fieldset": { borderColor: "#22c55e" },
                    },
                  }}
                />
                
                <Button
                  variant="outlined"
                  size="small"
                  onClick={importOpenApiUrl}
                  disabled={openApiLoading || !openApiUrl.trim()}
                  startIcon={openApiLoading ? <CircularProgress size={16} /> : <DownloadIcon />}
                  sx={{ 
                    mb: 3,
                    borderColor: "#22c55e", 
                    color: "#4ade80",
                    "&:hover": { borderColor: "#16a34a", bgcolor: "rgba(34, 197, 94, 0.1)" }
                  }}
                >
                  Import from URL
                </Button>

                {/* Content Import */}
                <Accordion 
                  sx={{ 
                    bgcolor: "rgba(0,0,0,0.2)", 
                    mb: 2,
                    "&:before": { display: "none" },
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#4ade80" }} />}>
                    <Typography variant="body2" sx={{ color: "#4ade80" }}>
                      Or paste OpenAPI/Swagger content directly
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <TextField
                      fullWidth
                      size="small"
                      label="Target API URL"
                      placeholder="https://api.example.com"
                      value={openApiTargetUrl}
                      onChange={(e) => setOpenApiTargetUrl(e.target.value)}
                      sx={{
                        mb: 2,
                        "& .MuiOutlinedInput-root": {
                          "&:hover fieldset": { borderColor: "#22c55e" },
                        },
                      }}
                    />
                    <TextField
                      fullWidth
                      multiline
                      rows={6}
                      placeholder={`{\n  "openapi": "3.0.0",\n  "info": { "title": "My API", "version": "1.0" },\n  "paths": { ... }\n}`}
                      value={openApiContent}
                      onChange={(e) => setOpenApiContent(e.target.value)}
                      sx={{
                        mb: 2,
                        "& .MuiOutlinedInput-root": {
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          "&:hover fieldset": { borderColor: "#22c55e" },
                        },
                      }}
                    />
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={importOpenApiContent}
                      disabled={openApiLoading || !openApiContent.trim() || !openApiTargetUrl.trim()}
                      sx={{ 
                        borderColor: "#22c55e", 
                        color: "#4ade80",
                        "&:hover": { borderColor: "#16a34a", bgcolor: "rgba(34, 197, 94, 0.1)" }
                      }}
                    >
                      Import Content
                    </Button>
                  </AccordionDetails>
                </Accordion>

                {/* Status */}
                {openApiStatus && (
                  <Alert 
                    severity={openApiStatus.startsWith("✅") ? "success" : "error"}
                    sx={{ bgcolor: openApiStatus.startsWith("✅") ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)" }}
                  >
                    {openApiStatus}
                  </Alert>
                )}
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Custom Scan Policies Panel */}
        <Grid item xs={12}>
          <Accordion 
            expanded={policiesExpanded}
            onChange={() => setPoliciesExpanded(!policiesExpanded)}
            sx={{
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(168, 85, 247, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&.Mui-expanded": {
                margin: 0,
                border: "1px solid rgba(168, 85, 247, 0.5)",
              },
            }}
          >
            <AccordionSummary
              expandIcon={<ExpandMoreIcon sx={{ color: "#c084fc" }} />}
              sx={{
                "& .MuiAccordionSummary-content": { alignItems: "center", gap: 2 },
              }}
            >
              <TuneIcon sx={{ color: "#c084fc" }} />
              <Typography variant="h6" sx={{ color: "#c084fc", fontWeight: 600 }}>
                Custom Scan Policies
              </Typography>
              {scanPolicies.length > 0 && (
                <Chip 
                  label={`${scanPolicies.length} policies`} 
                  size="small" 
                  sx={{ bgcolor: "rgba(168, 85, 247, 0.2)", color: "#c084fc", ml: 1 }} 
                />
              )}
            </AccordionSummary>
            <AccordionDetails>
              <Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Create and manage custom scan policies to control which vulnerability checks are enabled.
                  Fine-tune scan intensity for specific use cases or compliance requirements.
                </Typography>

                <Grid container spacing={3}>
                  {/* Policy List */}
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#c084fc", mb: 2 }}>
                        Policies
                      </Typography>
                      
                      {/* Create New Policy */}
                      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                        <TextField
                          size="small"
                          placeholder="New policy name"
                          value={newPolicyName}
                          onChange={(e) => setNewPolicyName(e.target.value)}
                          sx={{
                            flex: 1,
                            "& .MuiOutlinedInput-root": {
                              "&:hover fieldset": { borderColor: "#a855f7" },
                            },
                          }}
                        />
                        <IconButton 
                          size="small" 
                          onClick={createPolicy}
                          disabled={policiesLoading || !newPolicyName.trim()}
                          sx={{ color: "#c084fc", bgcolor: "rgba(168, 85, 247, 0.1)" }}
                        >
                          <AddIcon />
                        </IconButton>
                      </Box>

                      {policiesLoading && scanPolicies.length === 0 ? (
                        <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}>
                          <CircularProgress size={24} sx={{ color: "#c084fc" }} />
                        </Box>
                      ) : scanPolicies.length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                          No custom policies. Create one above.
                        </Typography>
                      ) : (
                        <List dense sx={{ maxHeight: 250, overflow: "auto" }}>
                          {scanPolicies.map((policy) => (
                            <ListItem
                              key={policy.id || policy.name}
                              sx={{
                                bgcolor: selectedPolicy === policy.name ? "rgba(168, 85, 247, 0.2)" : "transparent",
                                borderRadius: 1,
                                cursor: "pointer",
                                "&:hover": { bgcolor: "rgba(168, 85, 247, 0.1)" },
                              }}
                              onClick={() => setSelectedPolicy(policy.name)}
                              secondaryAction={
                                <IconButton 
                                  size="small" 
                                  onClick={(e) => { e.stopPropagation(); deletePolicy(policy.name); }}
                                >
                                  <DeleteIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                                </IconButton>
                              }
                            >
                              <ListItemText
                                primary={
                                  <Typography variant="body2" sx={{ color: "#fff" }}>
                                    {policy.name}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      )}
                    </Paper>
                  </Grid>

                  {/* Scanner List */}
                  <Grid item xs={12} md={8}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", height: "100%" }}>
                      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
                        <Typography variant="subtitle2" sx={{ color: "#c084fc" }}>
                          {selectedPolicy ? `Scanners in "${selectedPolicy}"` : "Select a policy"}
                        </Typography>
                        {selectedPolicy && (
                          <Box sx={{ display: "flex", gap: 1 }}>
                            <Button
                              size="small"
                              onClick={() => zapClient.enableAllScanners(selectedPolicy).then(loadPolicyScanners.bind(null, selectedPolicy))}
                              sx={{ color: "#4ade80", fontSize: "0.7rem" }}
                            >
                              Enable All
                            </Button>
                            <Button
                              size="small"
                              onClick={() => zapClient.disableAllScanners(selectedPolicy).then(loadPolicyScanners.bind(null, selectedPolicy))}
                              sx={{ color: "#ef4444", fontSize: "0.7rem" }}
                            >
                              Disable All
                            </Button>
                          </Box>
                        )}
                      </Box>

                      {!selectedPolicy ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
                          Select a policy from the left to view and configure its scanners.
                        </Typography>
                      ) : policiesLoading ? (
                        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
                          <CircularProgress size={32} sx={{ color: "#c084fc" }} />
                        </Box>
                      ) : (
                        <Box sx={{ maxHeight: 300, overflow: "auto" }}>
                          <Grid container spacing={1}>
                            {policyScanners.map((scanner) => (
                              <Grid item xs={12} sm={6} key={scanner.id}>
                                <Paper 
                                  sx={{ 
                                    p: 1.5, 
                                    bgcolor: scanner.enabled ? "rgba(16, 185, 129, 0.1)" : "rgba(0,0,0,0.2)",
                                    border: `1px solid ${scanner.enabled ? "rgba(16, 185, 129, 0.3)" : "rgba(255,255,255,0.1)"}`,
                                    borderRadius: 1,
                                  }}
                                >
                                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                                    <Box sx={{ flex: 1, minWidth: 0 }}>
                                      <Typography 
                                        variant="body2" 
                                        sx={{ 
                                          color: scanner.enabled ? "#10b981" : "rgba(255,255,255,0.5)",
                                          fontWeight: scanner.enabled ? 600 : 400,
                                          fontSize: "0.75rem",
                                          overflow: "hidden",
                                          textOverflow: "ellipsis",
                                          whiteSpace: "nowrap",
                                        }}
                                      >
                                        {scanner.name}
                                      </Typography>
                                      {scanner.cweId > 0 && (
                                        <Typography variant="caption" color="text.secondary">
                                          CWE-{scanner.cweId}
                                        </Typography>
                                      )}
                                    </Box>
                                    <Switch
                                      size="small"
                                      checked={scanner.enabled}
                                      onChange={(e) => toggleScanner(scanner.id, e.target.checked)}
                                      sx={{ 
                                        "& .Mui-checked": { color: "#10b981" },
                                        "& .Mui-checked + .MuiSwitch-track": { bgcolor: "#10b981" },
                                      }}
                                    />
                                  </Box>
                                </Paper>
                              </Grid>
                            ))}
                          </Grid>
                        </Box>
                      )}
                    </Paper>
                  </Grid>
                </Grid>
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Context Management Panel */}
        <Grid item xs={12}>
          <Accordion 
            expanded={contextsExpanded}
            onChange={() => setContextsExpanded(!contextsExpanded)}
            sx={{ 
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(59, 130, 246, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&:hover": { border: "1px solid rgba(59, 130, 246, 0.5)" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#60a5fa" }} />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <FolderOpenIcon sx={{ color: "#60a5fa" }} />
                <Typography variant="h6" sx={{ color: "#60a5fa", fontWeight: 600 }}>
                  Context & Authentication
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ p: 1 }}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Manage scan contexts with include/exclude URL patterns and technology filtering. Contexts help define the scope of your security tests.
                </Typography>
                
                <Grid container spacing={2}>
                  {/* Context List */}
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", height: "100%" }}>
                      <Typography variant="subtitle2" sx={{ color: "#60a5fa", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <FolderOpenIcon sx={{ fontSize: 18 }} /> Contexts
                      </Typography>
                      
                      {/* Create New Context */}
                      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                        <TextField
                          size="small"
                          placeholder="New context name"
                          value={newContextName}
                          onChange={(e) => setNewContextName(e.target.value)}
                          sx={{
                            flex: 1,
                            "& .MuiOutlinedInput-root": {
                              "&:hover fieldset": { borderColor: "#60a5fa" },
                            },
                          }}
                        />
                        <IconButton 
                          size="small" 
                          onClick={createContext}
                          disabled={contextsLoading || !newContextName.trim()}
                          sx={{ color: "#60a5fa", bgcolor: "rgba(59, 130, 246, 0.1)" }}
                        >
                          <AddIcon />
                        </IconButton>
                      </Box>

                      {contextsLoading && contexts.length === 0 ? (
                        <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}>
                          <CircularProgress size={24} sx={{ color: "#60a5fa" }} />
                        </Box>
                      ) : contexts.length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                          No contexts. Create one to define scan scope.
                        </Typography>
                      ) : (
                        <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                          {contexts.map((ctx) => (
                            <ListItem
                              key={ctx}
                              sx={{
                                bgcolor: selectedContext === ctx ? "rgba(59, 130, 246, 0.2)" : "transparent",
                                borderRadius: 1,
                                cursor: "pointer",
                                "&:hover": { bgcolor: "rgba(59, 130, 246, 0.1)" },
                              }}
                              onClick={() => setSelectedContext(ctx)}
                              secondaryAction={
                                <IconButton 
                                  size="small" 
                                  onClick={(e) => { e.stopPropagation(); deleteContext(ctx); }}
                                >
                                  <DeleteIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                                </IconButton>
                              }
                            >
                              <ListItemText
                                primary={
                                  <Typography variant="body2" sx={{ color: "#fff" }}>
                                    {ctx}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      )}
                    </Paper>
                  </Grid>

                  {/* Context Details */}
                  <Grid item xs={12} md={8}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", height: "100%" }}>
                      {!selectedContext ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
                          Select a context from the left to configure it.
                        </Typography>
                      ) : (
                        <Box>
                          <Typography variant="subtitle2" sx={{ color: "#60a5fa", mb: 2 }}>
                            Context: {selectedContext}
                          </Typography>
                          
                          {/* Include Patterns */}
                          <Box sx={{ mb: 3 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                              Include Patterns (URLs to scan)
                            </Typography>
                            <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                              <TextField
                                size="small"
                                placeholder="Regex pattern (e.g., .*example.com.*)"
                                value={newIncludeRegex}
                                onChange={(e) => setNewIncludeRegex(e.target.value)}
                                fullWidth
                                sx={{
                                  "& .MuiOutlinedInput-root": {
                                    "&:hover fieldset": { borderColor: "#4ade80" },
                                  },
                                }}
                              />
                              <IconButton 
                                size="small" 
                                onClick={addIncludeRegex}
                                disabled={!newIncludeRegex.trim()}
                                sx={{ color: "#4ade80" }}
                              >
                                <AddIcon />
                              </IconButton>
                            </Box>
                            {contextDetails?.includeRegexs && contextDetails.includeRegexs.length > 0 && (
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                {contextDetails.includeRegexs.map((regex: string, idx: number) => (
                                  <Chip 
                                    key={idx}
                                    label={regex}
                                    size="small"
                                    sx={{ bgcolor: "rgba(74, 222, 128, 0.2)", color: "#4ade80", fontSize: "0.7rem" }}
                                  />
                                ))}
                              </Box>
                            )}
                          </Box>
                          
                          {/* Exclude Patterns */}
                          <Box sx={{ mb: 3 }}>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                              Exclude Patterns (URLs to skip)
                            </Typography>
                            <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                              <TextField
                                size="small"
                                placeholder="Regex pattern (e.g., .*logout.*)"
                                value={newExcludeRegex}
                                onChange={(e) => setNewExcludeRegex(e.target.value)}
                                fullWidth
                                sx={{
                                  "& .MuiOutlinedInput-root": {
                                    "&:hover fieldset": { borderColor: "#ef4444" },
                                  },
                                }}
                              />
                              <IconButton 
                                size="small" 
                                onClick={addExcludeRegex}
                                disabled={!newExcludeRegex.trim()}
                                sx={{ color: "#ef4444" }}
                              >
                                <AddIcon />
                              </IconButton>
                            </Box>
                            {contextDetails?.excludeRegexs && contextDetails.excludeRegexs.length > 0 && (
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                {contextDetails.excludeRegexs.map((regex: string, idx: number) => (
                                  <Chip 
                                    key={idx}
                                    label={regex}
                                    size="small"
                                    sx={{ bgcolor: "rgba(239, 68, 68, 0.2)", color: "#ef4444", fontSize: "0.7rem" }}
                                  />
                                ))}
                              </Box>
                            )}
                          </Box>
                          
                          {/* Technologies */}
                          <Box>
                            <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                              Included Technologies
                            </Typography>
                            {contextDetails?.includedTechnologies && contextDetails.includedTechnologies.length > 0 ? (
                              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                {contextDetails.includedTechnologies.map((tech: string, idx: number) => (
                                  <Chip 
                                    key={idx}
                                    label={tech}
                                    size="small"
                                    sx={{ bgcolor: "rgba(59, 130, 246, 0.2)", color: "#60a5fa", fontSize: "0.7rem" }}
                                  />
                                ))}
                              </Box>
                            ) : (
                              <Typography variant="body2" color="text.secondary" sx={{ fontStyle: "italic" }}>
                                All technologies included by default
                              </Typography>
                            )}
                          </Box>
                        </Box>
                      )}
                    </Paper>
                  </Grid>
                </Grid>
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Forced Browse / Directory Discovery Panel */}
        <Grid item xs={12}>
          <Accordion 
            expanded={forcedBrowseExpanded}
            onChange={() => setForcedBrowseExpanded(!forcedBrowseExpanded)}
            sx={{ 
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(251, 146, 60, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&:hover": { border: "1px solid rgba(251, 146, 60, 0.5)" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#fb923c" }} />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <ExploreIcon sx={{ color: "#fb923c" }} />
                <Typography variant="h6" sx={{ color: "#fb923c", fontWeight: 600 }}>
                  Forced Browse / Directory Discovery
                </Typography>
                {forcedBrowseResults.length > 0 && (
                  <Chip 
                    label={`${forcedBrowseResults.length} found`} 
                    size="small" 
                    sx={{ bgcolor: "rgba(251, 146, 60, 0.2)", color: "#fb923c" }} 
                  />
                )}
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ p: 1 }}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Discover hidden directories and files using local wordlists. Runs entirely offline without requiring external services.
                </Typography>
                
                <Grid container spacing={2}>
                  {/* Scan Controls */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)" }}>
                      <Typography variant="subtitle2" sx={{ color: "#fb923c", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <ExploreIcon sx={{ fontSize: 18 }} /> Scan Configuration
                      </Typography>
                      
                      <TextField
                        fullWidth
                        size="small"
                        label="Target URL"
                        placeholder="https://example.com/"
                        value={forcedBrowseUrl}
                        onChange={(e) => setForcedBrowseUrl(e.target.value)}
                        sx={{
                          mb: 2,
                          "& .MuiOutlinedInput-root": {
                            "&:hover fieldset": { borderColor: "#fb923c" },
                          },
                        }}
                      />
                      
                      {/* Wordlist Selection */}
                      <FormControl fullWidth size="small" sx={{ mb: 2 }}>
                        <InputLabel sx={{ "&.Mui-focused": { color: "#fb923c" } }}>Wordlist</InputLabel>
                        <Select
                          value={selectedWordlist || defaultWordlist}
                          onChange={(e) => setSelectedWordlist(e.target.value as string)}
                          label="Wordlist"
                          sx={{
                            "& .MuiOutlinedInput-notchedOutline": { borderColor: "rgba(255,255,255,0.2)" },
                            "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "#fb923c" },
                            "&.Mui-focused .MuiOutlinedInput-notchedOutline": { borderColor: "#fb923c" },
                          }}
                        >
                          {wordlists.map((wl) => (
                            <MenuItem key={wl} value={wl}>
                              {wl} {wl === defaultWordlist && "(default)"}
                            </MenuItem>
                          ))}
                        </Select>
                      </FormControl>
                      
                      <Box sx={{ display: "flex", gap: 2, mb: 2 }}>
                        <TextField
                          size="small"
                          type="number"
                          label="Threads"
                          value={forcedBrowseThreads}
                          onChange={(e) => setForcedBrowseThreads(parseInt(e.target.value) || 10)}
                          inputProps={{ min: 1, max: 50 }}
                          sx={{
                            width: 100,
                            "& .MuiOutlinedInput-root": {
                              "&:hover fieldset": { borderColor: "#fb923c" },
                            },
                          }}
                        />
                        <FormControlLabel
                          control={
                            <Switch
                              checked={forcedBrowseRecursive}
                              onChange={(e) => setForcedBrowseRecursive(e.target.checked)}
                              sx={{ 
                                "& .Mui-checked": { color: "#fb923c" },
                                "& .Mui-checked + .MuiSwitch-track": { bgcolor: "#fb923c" },
                              }}
                            />
                          }
                          label={<Typography variant="body2" color="text.secondary">Recursive</Typography>}
                        />
                      </Box>
                      
                      <Box sx={{ display: "flex", gap: 1 }}>
                        <Button
                          variant="contained"
                          startIcon={forcedBrowseLoading ? <CircularProgress size={16} /> : <PlayArrowIcon />}
                          onClick={startForcedBrowse}
                          disabled={forcedBrowseLoading || !forcedBrowseUrl.trim()}
                          sx={{ 
                            bgcolor: "#fb923c",
                            "&:hover": { bgcolor: "#f97316" },
                            flex: 1,
                          }}
                        >
                          Start Discovery
                        </Button>
                        {forcedBrowseStatus === "running" && (
                          <Button
                            variant="outlined"
                            startIcon={<PauseIcon />}
                            onClick={pauseForcedBrowse}
                            sx={{ 
                              borderColor: "#fbbf24",
                              color: "#fbbf24",
                              "&:hover": { borderColor: "#f59e0b", bgcolor: "rgba(251, 191, 36, 0.1)" },
                            }}
                          >
                            Pause
                          </Button>
                        )}
                        {forcedBrowseStatus === "paused" && (
                          <Button
                            variant="outlined"
                            startIcon={<PlayArrowIcon />}
                            onClick={resumeForcedBrowse}
                            sx={{ 
                              borderColor: "#22c55e",
                              color: "#22c55e",
                              "&:hover": { borderColor: "#16a34a", bgcolor: "rgba(34, 197, 94, 0.1)" },
                            }}
                          >
                            Resume
                          </Button>
                        )}
                        <Button
                          variant="outlined"
                          startIcon={<StopIcon />}
                          onClick={stopForcedBrowse}
                          disabled={forcedBrowseStatus === "idle" || forcedBrowseStatus === "completed" || forcedBrowseStatus === "stopped"}
                          sx={{ 
                            borderColor: "#ef4444",
                            color: "#ef4444",
                            "&:hover": { borderColor: "#dc2626", bgcolor: "rgba(239, 68, 68, 0.1)" },
                          }}
                        >
                          Stop
                        </Button>
                      </Box>
                      
                      {/* Progress */}
                      {forcedBrowseStatus !== "idle" && (
                        <Box sx={{ mt: 2 }}>
                          <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
                            <Typography variant="caption" color="text.secondary">
                              Status: {forcedBrowseStatus}
                            </Typography>
                            <Typography variant="caption" sx={{ color: "#fb923c" }}>
                              {forcedBrowseProgress}%
                            </Typography>
                          </Box>
                          <LinearProgress 
                            variant="determinate" 
                            value={forcedBrowseProgress}
                            sx={{
                              bgcolor: "rgba(251, 146, 60, 0.1)",
                              "& .MuiLinearProgress-bar": { bgcolor: "#fb923c" },
                            }}
                          />
                        </Box>
                      )}
                    </Paper>
                  </Grid>
                  
                  {/* Results */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)", maxHeight: 400, overflow: "auto" }}>
                      <Typography variant="subtitle2" sx={{ color: "#fb923c", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <DescriptionIcon sx={{ fontSize: 18 }} /> 
                        Discovered Paths ({forcedBrowseResults.length})
                      </Typography>
                      
                      {forcedBrowseResults.length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 4 }}>
                          {forcedBrowseStatus === "idle" 
                            ? "Start a scan to discover hidden directories and files" 
                            : forcedBrowseStatus === "running" 
                            ? "Scanning in progress..." 
                            : "No paths discovered"}
                        </Typography>
                      ) : (
                        <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                          {forcedBrowseResults.map((result, idx) => (
                            <ListItem 
                              key={idx}
                              sx={{
                                bgcolor: result.status_code < 300 ? "rgba(34, 197, 94, 0.1)" : 
                                         result.status_code < 400 ? "rgba(251, 191, 36, 0.1)" :
                                         "rgba(251, 146, 60, 0.1)",
                                borderRadius: 1,
                                mb: 0.5,
                              }}
                            >
                              <ListItemText
                                primary={
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                    <Chip 
                                      label={result.status_code} 
                                      size="small"
                                      sx={{ 
                                        fontSize: 11,
                                        height: 20,
                                        bgcolor: result.status_code < 300 ? "rgba(34, 197, 94, 0.3)" : 
                                                 result.status_code < 400 ? "rgba(251, 191, 36, 0.3)" :
                                                 "rgba(251, 146, 60, 0.3)",
                                        color: "#fff",
                                      }}
                                    />
                                    <Typography variant="body2" sx={{ color: "#fff", wordBreak: "break-all" }}>
                                      {result.url}
                                    </Typography>
                                  </Box>
                                }
                                secondary={
                                  <Typography variant="caption" color="text.secondary">
                                    {result.content_length ? `${result.content_length} bytes` : ""}
                                    {result.content_type ? ` • ${result.content_type}` : ""}
                                  </Typography>
                                }
                              />
                              <IconButton 
                                size="small" 
                                onClick={() => window.open(result.url, '_blank')}
                                sx={{ color: "#fb923c" }}
                              >
                                <OpenInNewIcon sx={{ fontSize: 16 }} />
                              </IconButton>
                            </ListItem>
                          ))}
                        </List>
                      )}
                      
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
                        💡 Green = 2xx success, Yellow = 3xx redirect, Orange = 4xx/5xx
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Script Console Panel */}
        <Grid item xs={12}>
          <Accordion 
            expanded={scriptsExpanded}
            onChange={() => setScriptsExpanded(!scriptsExpanded)}
            sx={{ 
              bgcolor: "rgba(17, 24, 39, 0.9)",
              border: "1px solid rgba(34, 197, 94, 0.3)",
              borderRadius: "12px !important",
              "&:before": { display: "none" },
              "&:hover": { border: "1px solid rgba(34, 197, 94, 0.5)" },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#22c55e" }} />}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                <TerminalIcon sx={{ color: "#22c55e" }} />
                <Typography variant="h6" sx={{ color: "#22c55e", fontWeight: 600 }}>
                  Script Console
                </Typography>
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              <Box sx={{ p: 1 }}>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Manage ZAP scripts for custom automation, authentication, and scan logic. Scripts run locally without external dependencies.
                </Typography>
                
                <Grid container spacing={2}>
                  {/* Script List */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <CodeIcon sx={{ fontSize: 18 }} /> Scripts
                      </Typography>
                      
                      {scriptsLoading && scripts.length === 0 ? (
                        <Box sx={{ display: "flex", justifyContent: "center", py: 2 }}>
                          <CircularProgress size={24} sx={{ color: "#22c55e" }} />
                        </Box>
                      ) : scripts.length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                          No scripts loaded. Scripts can be loaded from ZAP's script directory.
                        </Typography>
                      ) : (
                        <List dense sx={{ maxHeight: 250, overflow: "auto" }}>
                          {scripts.map((script, idx) => (
                            <ListItem
                              key={idx}
                              sx={{
                                bgcolor: script.enabled ? "rgba(34, 197, 94, 0.1)" : "transparent",
                                borderRadius: 1,
                                mb: 0.5,
                              }}
                              secondaryAction={
                                <Box sx={{ display: "flex", gap: 0.5 }}>
                                  {script.type === "standalone" && (
                                    <IconButton 
                                      size="small" 
                                      onClick={() => runScript(script.name)}
                                      disabled={scriptsLoading}
                                    >
                                      <PlayArrowIcon sx={{ fontSize: 16, color: "#22c55e" }} />
                                    </IconButton>
                                  )}
                                  <IconButton 
                                    size="small" 
                                    onClick={() => removeScript(script.name)}
                                  >
                                    <DeleteIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                                  </IconButton>
                                </Box>
                              }
                            >
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Switch
                                  size="small"
                                  checked={script.enabled}
                                  onChange={(e) => toggleScript(script.name, e.target.checked)}
                                  sx={{ 
                                    "& .Mui-checked": { color: "#22c55e" },
                                    "& .Mui-checked + .MuiSwitch-track": { bgcolor: "#22c55e" },
                                  }}
                                />
                                <ListItemText
                                  primary={
                                    <Typography variant="body2" sx={{ color: script.enabled ? "#22c55e" : "rgba(255,255,255,0.7)" }}>
                                      {script.name}
                                    </Typography>
                                  }
                                  secondary={
                                    <Typography variant="caption" color="text.secondary">
                                      {script.type} • {script.engine}
                                    </Typography>
                                  }
                                />
                              </Box>
                            </ListItem>
                          ))}
                        </List>
                      )}
                      
                      {/* Engines Info */}
                      {scriptEngines.length > 0 && (
                        <Box sx={{ mt: 2 }}>
                          <Typography variant="caption" color="text.secondary">
                            Engines: {scriptEngines.map(e => e.name).join(", ")}
                          </Typography>
                        </Box>
                      )}
                    </Paper>
                  </Grid>
                  
                  {/* Script Variables */}
                  <Grid item xs={12} md={6}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(0,0,0,0.2)" }}>
                      <Typography variant="subtitle2" sx={{ color: "#22c55e", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                        <SettingsIcon sx={{ fontSize: 18 }} /> Global Variables
                      </Typography>
                      
                      {/* Add Variable */}
                      <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
                        <TextField
                          size="small"
                          placeholder="Variable name"
                          value={newScriptVarKey}
                          onChange={(e) => setNewScriptVarKey(e.target.value)}
                          sx={{
                            flex: 1,
                            "& .MuiOutlinedInput-root": {
                              "&:hover fieldset": { borderColor: "#22c55e" },
                            },
                          }}
                        />
                        <TextField
                          size="small"
                          placeholder="Value"
                          value={newScriptVarValue}
                          onChange={(e) => setNewScriptVarValue(e.target.value)}
                          sx={{
                            flex: 1,
                            "& .MuiOutlinedInput-root": {
                              "&:hover fieldset": { borderColor: "#22c55e" },
                            },
                          }}
                        />
                        <IconButton 
                          size="small" 
                          onClick={setScriptVar}
                          disabled={!newScriptVarKey.trim()}
                          sx={{ color: "#22c55e" }}
                        >
                          <AddIcon />
                        </IconButton>
                      </Box>
                      
                      {Object.keys(scriptVariables.global_vars || {}).length === 0 ? (
                        <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                          No global variables set. Add variables for scripts to use.
                        </Typography>
                      ) : (
                        <List dense sx={{ maxHeight: 150, overflow: "auto" }}>
                          {Object.entries(scriptVariables.global_vars || {}).map(([key, value]) => (
                            <ListItem
                              key={key}
                              secondaryAction={
                                <IconButton 
                                  size="small" 
                                  onClick={() => clearScriptVar(key)}
                                >
                                  <DeleteIcon sx={{ fontSize: 16, color: "#ef4444" }} />
                                </IconButton>
                              }
                            >
                              <ListItemText
                                primary={
                                  <Typography variant="body2" sx={{ color: "#fff" }}>
                                    <strong>{key}</strong>: {value}
                                  </Typography>
                                }
                              />
                            </ListItem>
                          ))}
                        </List>
                      )}
                      
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2 }}>
                        💡 Global variables can be accessed by all scripts for sharing configuration data.
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Box>
            </AccordionDetails>
          </Accordion>
        </Grid>

        {/* Full Width Results Panel */}
        <Grid item xs={12} ref={resultsPanelRef}>
          <Paper 
            sx={{ 
              p: 3, 
              borderRadius: 3, 
              bgcolor: "rgba(17, 24, 39, 0.9)", 
              border: "1px solid rgba(16, 185, 129, 0.2)", 
              minHeight: 600,
              backdropFilter: "blur(10px)",
              position: "relative",
              overflow: "hidden",
              transition: "all 0.3s ease",
              "&:hover": {
                border: "1px solid rgba(16, 185, 129, 0.4)",
              },
            }}
          >
            {/* Decorative corner elements */}
            <Box
              sx={{
                position: "absolute",
                top: 0,
                right: 0,
                width: 100,
                height: 100,
                background: "linear-gradient(135deg, transparent 50%, rgba(16, 185, 129, 0.1) 50%)",
                pointerEvents: "none",
              }}
            />
            
            {/* Header with tabs */}
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Typography variant="h5" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1, color: "#10b981" }}>
                <BugReportIcon sx={{ fontSize: 28, animation: filteredAlerts.length > 0 ? `${pulse} 2s ease-in-out infinite` : "none" }} />
                Scan Results
                {zapAlerts.length > 0 && (
                  <Chip 
                    label={`${zapAlerts.length} Alerts`}
                    size="small"
                    sx={{ 
                      ml: 1,
                      bgcolor: "rgba(239, 68, 68, 0.2)",
                      color: "#ef4444",
                      fontWeight: 700,
                      animation: `${pulse} 1.5s ease-in-out infinite`,
                    }} 
                  />
                )}
              </Typography>
              <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={zapAiAnalyzing ? <CircularProgress size={16} /> : <AutoAwesomeIcon />}
                  onClick={runZapAiAnalysis}
                  disabled={zapAiAnalyzing}
                  sx={{ borderColor: "#8b5cf6", color: "#8b5cf6", "&:hover": { borderColor: "#a78bfa", bgcolor: "rgba(139, 92, 246, 0.1)" } }}
                >
                  AI Analysis
                </Button>
                {zapAiAnalysis && (
                  <Button
                    variant="contained"
                    size="small"
                    startIcon={exportingReport ? <CircularProgress size={16} /> : <DownloadIcon />}
                    onClick={(e) => setExportMenuAnchor(e.currentTarget)}
                    disabled={exportingReport}
                    sx={{ 
                      bgcolor: "#10b981", 
                      "&:hover": { bgcolor: "#059669" },
                      fontWeight: 600,
                    }}
                  >
                    Export Report
                  </Button>
                )}
                <Menu
                  anchorEl={exportMenuAnchor}
                  open={Boolean(exportMenuAnchor)}
                  onClose={() => setExportMenuAnchor(null)}
                  PaperProps={{
                    sx: {
                      bgcolor: "#1a1a2e",
                      border: "1px solid rgba(16, 185, 129, 0.3)",
                      minWidth: 180,
                      "& .MuiMenuItem-root": {
                        color: "rgba(255,255,255,0.9)",
                        "&:hover": { bgcolor: "rgba(16, 185, 129, 0.2)" },
                      },
                    },
                  }}
                >
                  <MenuItem onClick={() => { exportAIReport("markdown"); setExportMenuAnchor(null); }}>
                    <ListItemIcon><DescriptionIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                    Markdown
                  </MenuItem>
                  <MenuItem onClick={() => { exportAIReport("pdf"); setExportMenuAnchor(null); }}>
                    <ListItemIcon><PictureAsPdfIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
                    PDF
                  </MenuItem>
                  <MenuItem onClick={() => { exportAIReport("word"); setExportMenuAnchor(null); }}>
                    <ListItemIcon><ArticleIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                    Word Document
                  </MenuItem>
                </Menu>
              </Box>
            </Box>

            {/* Results Tabs */}
            {zapAlerts.length > 0 && (
              <Tabs
                value={resultsTab}
                onChange={(_, newValue) => setResultsTab(newValue)}
                sx={{
                  mb: 3,
                  borderBottom: "1px solid rgba(16, 185, 129, 0.2)",
                  "& .MuiTab-root": { color: "rgba(255,255,255,0.5)", minHeight: 48 },
                  "& .Mui-selected": { color: "#10b981" },
                  "& .MuiTabs-indicator": { bgcolor: "#10b981" },
                }}
              >
                <Tab icon={<SummarizeIcon />} label="Executive Summary" iconPosition="start" />
                <Tab icon={<TableChartIcon />} label="All Alerts" iconPosition="start" />
                <Tab icon={<CategoryIcon />} label="By Category" iconPosition="start" />
                <Tab icon={<DomainIcon />} label="By URL" iconPosition="start" />
              </Tabs>
            )}

            {/* Executive Summary Tab */}
            {resultsTab === 0 && zapAlerts.length > 0 && (
              <Box sx={{ animation: `${glow} 0.5s ease-out` }}>
                {/* Risk Score Card */}
                <Paper 
                  sx={{ 
                    p: 3, 
                    mb: 3, 
                    background: riskStats.critical > 0 || riskStats.high > 0 
                      ? "linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(17, 24, 39, 0.95) 100%)"
                      : riskStats.medium > 0
                        ? "linear-gradient(135deg, rgba(245, 158, 11, 0.15) 0%, rgba(17, 24, 39, 0.95) 100%)"
                        : "linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(17, 24, 39, 0.95) 100%)",
                    border: `1px solid ${riskStats.critical > 0 || riskStats.high > 0 ? 'rgba(239, 68, 68, 0.3)' : riskStats.medium > 0 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                    borderRadius: 2,
                  }}
                >
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
                    <Box>
                      <Typography variant="h4" fontWeight={800} sx={{ 
                        color: riskStats.critical > 0 || riskStats.high > 0 ? "#ef4444" : riskStats.medium > 0 ? "#f59e0b" : "#10b981",
                        display: "flex",
                        alignItems: "center",
                        gap: 2,
                      }}>
                        <SecurityIcon sx={{ fontSize: 40 }} />
                        {riskStats.critical > 0 ? "CRITICAL" : riskStats.high > 0 ? "HIGH RISK" : riskStats.medium > 0 ? "MEDIUM RISK" : "LOW RISK"}
                      </Typography>
                      <Typography variant="body1" sx={{ color: "rgba(255,255,255,0.7)", mt: 1 }}>
                        Security Assessment for {zapTargetUrl || zapSelectedScan?.target_url || "Target"}
                      </Typography>
                    </Box>
                    <Box sx={{ textAlign: "right" }}>
                      <Typography variant="h2" fontWeight={800} sx={{ color: "#fff" }}>
                        {zapAlerts.length}
                      </Typography>
                      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        Total Vulnerabilities
                      </Typography>
                    </Box>
                  </Box>

                  {/* Risk Distribution */}
                  <Grid container spacing={2}>
                    {[
                      { label: "Critical", count: riskStats.critical, color: "#dc2626", icon: "🔴" },
                      { label: "High", count: riskStats.high, color: "#ef4444", icon: "🟠" },
                      { label: "Medium", count: riskStats.medium, color: "#f59e0b", icon: "🟡" },
                      { label: "Low", count: riskStats.low, color: "#3b82f6", icon: "🔵" },
                      { label: "Info", count: riskStats.info, color: "#6b7280", icon: "⚪" },
                    ].map(item => (
                      <Grid item xs={6} sm={2.4} key={item.label}>
                        <Paper sx={{ 
                          p: 2, 
                          textAlign: "center",
                          bgcolor: `${item.color}15`,
                          border: `1px solid ${item.color}40`,
                          borderRadius: 2,
                        }}>
                          <Typography variant="h4" fontWeight={800} sx={{ color: item.color }}>
                            {item.count}
                          </Typography>
                          <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.7)" }}>
                            {item.icon} {item.label}
                          </Typography>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Paper>

                {/* Key Metrics */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", border: "1px solid rgba(139, 92, 246, 0.3)", borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#a78bfa", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                        <CategoryIcon fontSize="small" /> Vulnerability Types
                      </Typography>
                      <Typography variant="h4" fontWeight={700} sx={{ color: "#fff" }}>
                        {Object.keys(groupedAlerts).length}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        Unique vulnerability categories
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.3)", borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                        <DomainIcon fontSize="small" /> Affected URLs
                      </Typography>
                      <Typography variant="h4" fontWeight={700} sx={{ color: "#fff" }}>
                        {uniqueUrls}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        Unique endpoints with issues
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <Paper sx={{ p: 2, bgcolor: "rgba(16, 185, 129, 0.1)", border: "1px solid rgba(16, 185, 129, 0.3)", borderRadius: 2 }}>
                      <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                        <VerifiedIcon fontSize="small" /> AI Validated
                      </Typography>
                      <Typography variant="h4" fontWeight={700} sx={{ color: "#fff" }}>
                        {Object.keys(alertValidations).filter(k => alertValidations[k].validated).length}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        Alerts verified by AI
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Top Vulnerabilities */}
                <Paper sx={{ p: 3, bgcolor: "rgba(239, 68, 68, 0.05)", border: "1px solid rgba(239, 68, 68, 0.2)", borderRadius: 2, mb: 3 }}>
                  <Typography variant="h6" sx={{ color: "#ef4444", mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                    <WarningIcon /> Top Critical/High Vulnerabilities
                  </Typography>
                  {Object.entries(groupedAlerts)
                    .filter(([_, alerts]) => ['critical', 'high'].includes(getAlertRisk(alerts[0]).toLowerCase()))
                    .slice(0, 5)
                    .map(([name, alerts], idx) => (
                      <Box key={idx} sx={{ display: "flex", alignItems: "center", gap: 2, mb: 1.5, p: 1.5, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                        <Chip
                          label={getAlertRisk(alerts[0])}
                          size="small"
                          sx={{
                            bgcolor: `${getRiskColor(getAlertRisk(alerts[0]))}30`,
                            color: getRiskColor(getAlertRisk(alerts[0])),
                            fontWeight: 700,
                            minWidth: 70,
                          }}
                        />
                        <Typography variant="body2" sx={{ color: "#fff", flex: 1 }}>
                          {name}
                        </Typography>
                        <Chip label={`${alerts.length} instances`} size="small" variant="outlined" sx={{ borderColor: "rgba(255,255,255,0.3)" }} />
                      </Box>
                    ))}
                  {Object.entries(groupedAlerts).filter(([_, alerts]) => ['critical', 'high'].includes(getAlertRisk(alerts[0]).toLowerCase())).length === 0 && (
                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)", textAlign: "center", py: 2 }}>
                      ✅ No critical or high severity vulnerabilities found
                    </Typography>
                  )}
                </Paper>

                {/* Quick Actions - only show regenerate if AI analysis already exists */}
                {zapAiAnalysis && (
                  <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                    <Button
                      variant="outlined"
                      startIcon={zapAiAnalyzing ? <CircularProgress size={16} /> : <AutoAwesomeIcon />}
                      onClick={runZapAiAnalysis}
                      disabled={zapAiAnalyzing}
                      sx={{ 
                        borderColor: "#8b5cf6", 
                        color: "#8b5cf6",
                        "&:hover": { borderColor: "#a78bfa", bgcolor: "rgba(139, 92, 246, 0.1)" },
                      }}
                    >
                      Regenerate AI Analysis
                    </Button>
                  </Box>
                )}
              </Box>
            )}

            {/* All Alerts Tab */}
            {resultsTab === 1 && zapAlerts.length > 0 && (
              <Box>
                {/* Filter bar */}
                <Box sx={{ display: "flex", gap: 2, mb: 3, alignItems: "center" }}>
                  <FormControl size="small" sx={{ minWidth: 150 }}>
                    <InputLabel>Filter by Risk</InputLabel>
                    <Select
                      value={zapAlertFilter}
                      onChange={(e) => setZapAlertFilter(e.target.value)}
                      label="Filter by Risk"
                    >
                      <MenuItem value="all">All Risks</MenuItem>
                      <MenuItem value="critical">Critical</MenuItem>
                      <MenuItem value="high">High</MenuItem>
                      <MenuItem value="medium">Medium</MenuItem>
                      <MenuItem value="low">Low</MenuItem>
                      <MenuItem value="informational">Info</MenuItem>
                    </Select>
                  </FormControl>
                  <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                    Showing {filteredAlerts.length} of {zapAlerts.length} alerts
                  </Typography>
                </Box>

                {/* Alerts List */}
                <Box sx={{ maxHeight: 600, overflow: "auto", pr: 1 }}>
                  {filteredAlerts.map((alert, index) => {
                    const risk = getAlertRisk(alert);
                    const name = getAlertName(alert);
                    const url = getAlertUrl(alert);
                    const solution = getAlertSolution(alert);
                    const alertId = `alert_${index}`;
                    const validation = alertValidations[alertId];
                    const isExpanded = expandedAlertIndex === index;
                    
                    return (
                      <Card
                        key={index}
                        sx={{
                          mb: 2,
                          bgcolor: getRiskBgColor(risk),
                          border: `1px solid ${getRiskColor(risk)}30`,
                          borderLeft: `4px solid ${getRiskColor(risk)}`,
                          transition: "all 0.3s ease",
                          "&:hover": {
                            transform: "translateX(4px)",
                            boxShadow: `0 4px 20px ${getRiskColor(risk)}20`,
                          },
                        }}
                      >
                        <CardContent sx={{ pb: 1 }}>
                          <Box sx={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
                            <Box sx={{ flex: 1 }}>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, flexWrap: "wrap" }}>
                                <Chip
                                  label={risk}
                                  size="small"
                                  sx={{
                                    bgcolor: `${getRiskColor(risk)}30`,
                                    color: getRiskColor(risk),
                                    fontWeight: 700,
                                  }}
                                />
                                <Typography variant="subtitle1" fontWeight={600} sx={{ color: "#fff" }}>
                                  {name}
                                </Typography>
                                {validation?.validated && (
                                  <Chip
                                    icon={validation.falsePositive ? <ThumbDownIcon /> : <ThumbUpIcon />}
                                    label={validation.falsePositive ? "False Positive" : "Confirmed"}
                                    size="small"
                                    sx={{
                                      bgcolor: validation.falsePositive ? "rgba(107, 114, 128, 0.2)" : "rgba(16, 185, 129, 0.2)",
                                      color: validation.falsePositive ? "#6b7280" : "#10b981",
                                    }}
                                  />
                                )}
                              </Box>
                              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                {alert.description?.slice(0, isExpanded ? undefined : 150)}{!isExpanded && alert.description && alert.description.length > 150 ? '...' : ''}
                              </Typography>
                              <Typography 
                                variant="caption" 
                                sx={{ 
                                  color: "#10b981", 
                                  wordBreak: "break-all",
                                  display: "block",
                                  p: 1,
                                  bgcolor: "rgba(16, 185, 129, 0.1)",
                                  borderRadius: 1,
                                  fontFamily: "monospace",
                                }}
                              >
                                🔗 {url}
                              </Typography>
                            </Box>
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 1, ml: 2 }}>
                              <Tooltip title="AI Validate Alert">
                                <IconButton 
                                  size="small" 
                                  onClick={() => validateAlert(alert, index)}
                                  disabled={validatingAlertId === alertId}
                                  sx={{ color: validation?.validated ? "#10b981" : "#a78bfa" }}
                                >
                                  {validatingAlertId === alertId ? (
                                    <CircularProgress size={18} />
                                  ) : validation?.validated ? (
                                    <VerifiedIcon />
                                  ) : (
                                    <SmartToyIcon />
                                  )}
                                </IconButton>
                              </Tooltip>
                              <Chip
                                label={`CWE-${alert.cwe_id || "N/A"}`}
                                size="small"
                                variant="outlined"
                                sx={{ borderColor: "rgba(255,255,255,0.2)", color: "text.secondary" }}
                              />
                              <IconButton 
                                size="small" 
                                onClick={() => setExpandedAlertIndex(isExpanded ? null : index)}
                                sx={{ color: "rgba(255,255,255,0.5)" }}
                              >
                                {isExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                              </IconButton>
                            </Box>
                          </Box>
                          
                          <Collapse in={isExpanded}>
                            <Divider sx={{ my: 2, borderColor: "rgba(255,255,255,0.1)" }} />
                            
                            {/* Full details */}
                            {solution && (
                              <Box sx={{ mb: 2, p: 2, bgcolor: "rgba(16, 185, 129, 0.1)", borderRadius: 1, borderLeft: "3px solid #10b981" }}>
                                <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                  <BuildIcon fontSize="small" /> Solution
                                </Typography>
                                <Typography variant="body2" color="text.secondary">
                                  {solution}
                                </Typography>
                              </Box>
                            )}
                            
                            {(alert as ZAPAlert).attack && (
                              <Box sx={{ mb: 2, p: 2, bgcolor: "rgba(239, 68, 68, 0.1)", borderRadius: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>
                                  🎯 Attack Vector
                                </Typography>
                                <Typography variant="body2" sx={{ fontFamily: "monospace", color: "rgba(255,255,255,0.8)" }}>
                                  {(alert as ZAPAlert).attack}
                                </Typography>
                              </Box>
                            )}
                            
                            {(alert as ZAPAlert).evidence && (
                              <Box sx={{ mb: 2, p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", borderRadius: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: "#a78bfa", mb: 1 }}>
                                  📋 Evidence
                                </Typography>
                                <Typography variant="body2" sx={{ fontFamily: "monospace", color: "rgba(255,255,255,0.8)", whiteSpace: "pre-wrap" }}>
                                  {(alert as ZAPAlert).evidence}
                                </Typography>
                              </Box>
                            )}
                            
                            {(alert as ZAPAlert).reference && (
                              <Box sx={{ p: 2, bgcolor: "rgba(59, 130, 246, 0.1)", borderRadius: 1 }}>
                                <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1 }}>
                                  📚 References
                                </Typography>
                                <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", whiteSpace: "pre-wrap" }}>
                                  {(alert as ZAPAlert).reference}
                                </Typography>
                              </Box>
                            )}
                            
                            {validation?.notes && (
                              <Box sx={{ mt: 2, p: 2, bgcolor: "rgba(16, 185, 129, 0.1)", borderRadius: 1, borderLeft: "3px solid #a78bfa" }}>
                                <Typography variant="subtitle2" sx={{ color: "#a78bfa", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                  <SmartToyIcon fontSize="small" /> AI Validation Notes
                                </Typography>
                                <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                  {validation.notes}
                                </Typography>
                              </Box>
                            )}
                          </Collapse>
                        </CardContent>
                      </Card>
                    );
                  })}
                </Box>
              </Box>
            )}

            {/* By Category Tab */}
            {resultsTab === 2 && zapAlerts.length > 0 && (
              <Box sx={{ maxHeight: 700, overflow: "auto" }}>
                {Object.entries(groupedAlerts)
                  .sort((a, b) => {
                    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, info: 4 };
                    const riskA = getAlertRisk(a[1][0]).toLowerCase();
                    const riskB = getAlertRisk(b[1][0]).toLowerCase();
                    return (riskOrder[riskA as keyof typeof riskOrder] || 5) - (riskOrder[riskB as keyof typeof riskOrder] || 5);
                  })
                  .map(([name, alerts], idx) => {
                    const risk = getAlertRisk(alerts[0]);
                    return (
                      <Accordion 
                        key={idx}
                        sx={{ 
                          bgcolor: getRiskBgColor(risk),
                          mb: 1,
                          border: `1px solid ${getRiskColor(risk)}30`,
                          "&:before": { display: "none" },
                        }}
                      >
                        <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: getRiskColor(risk) }} />}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                            <Chip
                              label={risk}
                              size="small"
                              sx={{
                                bgcolor: `${getRiskColor(risk)}30`,
                                color: getRiskColor(risk),
                                fontWeight: 700,
                                minWidth: 80,
                              }}
                            />
                            <Typography sx={{ color: "#fff", fontWeight: 600, flex: 1 }}>
                              {name}
                            </Typography>
                            <Chip 
                              label={`${alerts.length} instances`} 
                              size="small" 
                              sx={{ bgcolor: "rgba(255,255,255,0.1)", color: "rgba(255,255,255,0.7)" }} 
                            />
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.7)", mb: 2 }}>
                            {alerts[0].description}
                          </Typography>
                          <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>
                            Affected URLs:
                          </Typography>
                          <Box sx={{ maxHeight: 200, overflow: "auto" }}>
                            {alerts.map((alert, i) => (
                              <Typography 
                                key={i} 
                                variant="caption" 
                                sx={{ 
                                  display: "block", 
                                  p: 0.5, 
                                  fontFamily: "monospace",
                                  color: "rgba(255,255,255,0.6)",
                                  "&:hover": { bgcolor: "rgba(255,255,255,0.05)" }
                                }}
                              >
                                • {getAlertUrl(alert)}
                              </Typography>
                            ))}
                          </Box>
                          {getAlertSolution(alerts[0]) && (
                            <Box sx={{ mt: 2, p: 2, bgcolor: "rgba(16, 185, 129, 0.1)", borderRadius: 1 }}>
                              <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1 }}>
                                ✅ Solution:
                              </Typography>
                              <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                {getAlertSolution(alerts[0])}
                              </Typography>
                            </Box>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    );
                  })}
              </Box>
            )}

            {/* By URL Tab */}
            {resultsTab === 3 && zapAlerts.length > 0 && (
              <Box sx={{ maxHeight: 700, overflow: "auto" }}>
                {Object.entries(
                  filteredAlerts.reduce((acc, alert) => {
                    const url = getAlertUrl(alert);
                    if (!acc[url]) acc[url] = [];
                    acc[url].push(alert);
                    return acc;
                  }, {} as Record<string, (ZAPAlert | ZAPFinding)[]>)
                )
                  .sort((a, b) => b[1].length - a[1].length)
                  .map(([url, alerts], idx) => (
                    <Accordion 
                      key={idx}
                      sx={{ 
                        bgcolor: "rgba(59, 130, 246, 0.05)",
                        mb: 1,
                        border: "1px solid rgba(59, 130, 246, 0.2)",
                        "&:before": { display: "none" },
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#3b82f6" }} />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%", minWidth: 0 }}>
                          <DomainIcon sx={{ color: "#3b82f6", flexShrink: 0 }} />
                          <Typography sx={{ color: "#fff", fontFamily: "monospace", fontSize: "0.85rem", overflow: "hidden", textOverflow: "ellipsis", flex: 1 }}>
                            {url}
                          </Typography>
                          <Box sx={{ display: "flex", gap: 0.5, flexShrink: 0 }}>
                            {["high", "medium", "low"].map(r => {
                              const count = alerts.filter(a => getAlertRisk(a).toLowerCase() === r).length;
                              if (count === 0) return null;
                              return (
                                <Chip 
                                  key={r}
                                  label={count} 
                                  size="small" 
                                  sx={{ 
                                    bgcolor: `${getRiskColor(r)}30`,
                                    color: getRiskColor(r),
                                    minWidth: 28,
                                  }} 
                                />
                              );
                            })}
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        {alerts.map((alert, i) => (
                          <Box key={i} sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1, p: 1, bgcolor: "rgba(0,0,0,0.2)", borderRadius: 1 }}>
                            <Chip
                              label={getAlertRisk(alert)}
                              size="small"
                              sx={{
                                bgcolor: `${getRiskColor(getAlertRisk(alert))}30`,
                                color: getRiskColor(getAlertRisk(alert)),
                                fontWeight: 700,
                                minWidth: 70,
                              }}
                            />
                            <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                              {getAlertName(alert)}
                            </Typography>
                          </Box>
                        ))}
                      </AccordionDetails>
                    </Accordion>
                  ))}
              </Box>
            )}

            {/* AI Analysis Panel - Enhanced */}
            <Collapse in={zapShowAiPanel && zapAiAnalysis !== null}>
              <Paper 
                sx={{ 
                  mb: 3, 
                  bgcolor: "rgba(139, 92, 246, 0.05)", 
                  border: "1px solid rgba(139, 92, 246, 0.3)", 
                  borderRadius: 2,
                  overflow: "hidden",
                }}
              >
                {/* Header */}
                <Box 
                  sx={{ 
                    display: "flex", 
                    alignItems: "center", 
                    justifyContent: "space-between", 
                    p: 2,
                    bgcolor: "rgba(139, 92, 246, 0.1)",
                    borderBottom: "1px solid rgba(139, 92, 246, 0.2)",
                  }}
                >
                  <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
                    <Box
                      sx={{
                        width: 40,
                        height: 40,
                        borderRadius: "50%",
                        bgcolor: "rgba(139, 92, 246, 0.2)",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <PsychologyIcon sx={{ color: "#a78bfa" }} />
                    </Box>
                    <Box>
                      <Typography variant="h6" sx={{ color: "#a78bfa", fontWeight: 700 }}>
                        🔒 Offensive Security Analysis
                      </Typography>
                      <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.6)" }}>
                        AI-powered penetration testing insights
                      </Typography>
                    </Box>
                  </Box>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    {zapAiAnalysis && (
                      <>
                        <Chip
                          label={`${zapAiAnalysis.risk_level?.toUpperCase()} RISK`}
                          size="small"
                          sx={{
                            bgcolor: zapAiAnalysis.risk_level === "critical" ? "rgba(239, 68, 68, 0.2)" :
                                     zapAiAnalysis.risk_level === "high" ? "rgba(249, 115, 22, 0.2)" :
                                     zapAiAnalysis.risk_level === "medium" ? "rgba(245, 158, 11, 0.2)" :
                                     "rgba(16, 185, 129, 0.2)",
                            color: zapAiAnalysis.risk_level === "critical" ? "#ef4444" :
                                   zapAiAnalysis.risk_level === "high" ? "#f97316" :
                                   zapAiAnalysis.risk_level === "medium" ? "#f59e0b" :
                                   "#10b981",
                            fontWeight: 700,
                          }}
                        />
                        <Button
                          variant="contained"
                          size="small"
                          startIcon={exportingReport ? <CircularProgress size={16} /> : <DownloadIcon />}
                          onClick={(e) => setExportMenuAnchor(e.currentTarget)}
                          disabled={exportingReport}
                          sx={{ 
                            bgcolor: "#a78bfa", 
                            "&:hover": { bgcolor: "#8b5cf6" },
                            fontWeight: 600,
                            px: 2,
                          }}
                        >
                          Export Report
                        </Button>
                        <Menu
                          anchorEl={exportMenuAnchor}
                          open={Boolean(exportMenuAnchor)}
                          onClose={() => setExportMenuAnchor(null)}
                          PaperProps={{
                            sx: {
                              bgcolor: "#1a1a2e",
                              border: "1px solid rgba(139, 92, 246, 0.3)",
                              minWidth: 180,
                              "& .MuiMenuItem-root": {
                                color: "rgba(255,255,255,0.9)",
                                "&:hover": { bgcolor: "rgba(139, 92, 246, 0.2)" },
                              },
                            },
                          }}
                        >
                          <MenuItem onClick={() => { exportAIReport("markdown"); setExportMenuAnchor(null); }}>
                            <ListItemIcon><DescriptionIcon sx={{ color: "#10b981" }} /></ListItemIcon>
                            Markdown
                          </MenuItem>
                          <MenuItem onClick={() => { exportAIReport("pdf"); setExportMenuAnchor(null); }}>
                            <ListItemIcon><PictureAsPdfIcon sx={{ color: "#ef4444" }} /></ListItemIcon>
                            PDF
                          </MenuItem>
                          <MenuItem onClick={() => { exportAIReport("word"); setExportMenuAnchor(null); }}>
                            <ListItemIcon><ArticleIcon sx={{ color: "#3b82f6" }} /></ListItemIcon>
                            Word Document
                          </MenuItem>
                        </Menu>
                      </>
                    )}
                    <IconButton size="small" onClick={() => setZapShowAiPanel(false)} sx={{ color: "rgba(255,255,255,0.5)" }}>
                      <ExpandLessIcon />
                    </IconButton>
                  </Box>
                </Box>

                {zapAiAnalysis && (
                  <Box>
                    {/* Tabs */}
                    <Tabs
                      value={aiAnalysisTab}
                      onChange={(_, newValue) => setAiAnalysisTab(newValue)}
                      sx={{
                        borderBottom: "1px solid rgba(139, 92, 246, 0.2)",
                        "& .MuiTab-root": {
                          color: "rgba(255,255,255,0.5)",
                          "&.Mui-selected": { color: "#a78bfa" },
                        },
                        "& .MuiTabs-indicator": { bgcolor: "#a78bfa" },
                      }}
                    >
                      <Tab icon={<AssessmentIcon />} label="Summary" iconPosition="start" />
                      <Tab icon={<LinkIcon />} label="Attack Chains" iconPosition="start" />
                      <Tab icon={<BuildIcon />} label="Remediation" iconPosition="start" />
                      <Tab icon={<TimelineIcon />} label="Attack Narrative" iconPosition="start" />
                      <Tab icon={<TrendingUpIcon />} label="Insights" iconPosition="start" />
                    </Tabs>

                    {/* Tab Panels */}
                    <Box sx={{ p: 3, maxHeight: 500, overflow: "auto" }}>
                      {/* Summary Tab */}
                      {aiAnalysisTab === 0 && (
                        <Box 
                          sx={{ 
                            color: "rgba(255,255,255,0.9)",
                            "& h1, & h2, & h3, & h4": { color: "#a78bfa", mt: 2, mb: 1 },
                            "& strong": { color: "#10b981" },
                            "& ul, & ol": { pl: 3 },
                            "& li": { mb: 0.5 },
                            "& code": { 
                              bgcolor: "rgba(0,0,0,0.3)", 
                              px: 1, 
                              py: 0.5, 
                              borderRadius: 1,
                              fontFamily: "monospace",
                            },
                            "& pre": {
                              bgcolor: "rgba(0,0,0,0.4)",
                              p: 2,
                              borderRadius: 1,
                              overflow: "auto",
                            },
                          }}
                        >
                          <ReactMarkdown>{zapAiAnalysis.summary}</ReactMarkdown>
                          
                          {zapAiAnalysis.business_impact && (
                            <Box sx={{ mt: 3, p: 2, bgcolor: "rgba(249, 115, 22, 0.1)", borderRadius: 2, borderLeft: "4px solid #f97316" }}>
                              <Typography variant="subtitle2" sx={{ color: "#f97316", mb: 1, fontWeight: 700 }}>
                                💼 Business Impact
                              </Typography>
                              <Box sx={{ 
                                "& h1, & h2, & h3, & h4": { color: "#f97316", fontSize: "1rem", mt: 1, mb: 0.5 },
                                "& p": { mb: 1 },
                              }}>
                                <ReactMarkdown>{zapAiAnalysis.business_impact}</ReactMarkdown>
                              </Box>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Attack Chains Tab */}
                      {aiAnalysisTab === 1 && (
                        <Box>
                          {zapAiAnalysis.exploit_chains && zapAiAnalysis.exploit_chains.length > 0 ? (
                            zapAiAnalysis.exploit_chains.map((chain, index) => (
                              <Accordion 
                                key={index}
                                sx={{ 
                                  bgcolor: "rgba(239, 68, 68, 0.05)", 
                                  mb: 2,
                                  border: "1px solid rgba(239, 68, 68, 0.2)",
                                  "&:before": { display: "none" },
                                }}
                              >
                                <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "#ef4444" }} />}>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                                    <Chip
                                      label={chain.severity?.toUpperCase()}
                                      size="small"
                                      sx={{
                                        bgcolor: chain.severity === "critical" ? "rgba(239, 68, 68, 0.3)" :
                                                 chain.severity === "high" ? "rgba(249, 115, 22, 0.3)" :
                                                 "rgba(245, 158, 11, 0.3)",
                                        color: chain.severity === "critical" ? "#ef4444" :
                                               chain.severity === "high" ? "#f97316" :
                                               "#f59e0b",
                                        fontWeight: 700,
                                      }}
                                    />
                                    <Typography sx={{ color: "#fff", fontWeight: 600 }}>
                                      ⛓️ {chain.title}
                                    </Typography>
                                    {chain.difficulty && (
                                      <Chip
                                        label={`Difficulty: ${chain.difficulty}`}
                                        size="small"
                                        variant="outlined"
                                        sx={{ ml: "auto", borderColor: "rgba(255,255,255,0.3)", color: "rgba(255,255,255,0.7)" }}
                                      />
                                    )}
                                  </Box>
                                </AccordionSummary>
                                <AccordionDetails>
                                  <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)", mb: 2 }}>
                                    {chain.description}
                                  </Typography>
                                  
                                  <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1 }}>
                                    📋 Attack Steps:
                                  </Typography>
                                  <List dense>
                                    {chain.steps?.map((step, stepIndex) => (
                                      <ListItem key={stepIndex} sx={{ py: 0.5 }}>
                                        <Chip label={stepIndex + 1} size="small" sx={{ mr: 1, bgcolor: "rgba(239, 68, 68, 0.2)", color: "#ef4444", minWidth: 24 }} />
                                        <ListItemText primary={step} sx={{ "& .MuiTypography-root": { color: "rgba(255,255,255,0.8)" } }} />
                                      </ListItem>
                                    ))}
                                  </List>
                                  
                                  {chain.tools && chain.tools.length > 0 && (
                                    <Box sx={{ mt: 2 }}>
                                      <Typography variant="subtitle2" sx={{ color: "#a78bfa", mb: 1 }}>
                                        🛠️ Tools:
                                      </Typography>
                                      <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                                        {chain.tools.map((tool, toolIndex) => (
                                          <Chip key={toolIndex} label={tool} size="small" sx={{ bgcolor: "rgba(139, 92, 246, 0.2)", color: "#a78bfa" }} />
                                        ))}
                                      </Box>
                                    </Box>
                                  )}
                                  
                                  {chain.real_world_impact && (
                                    <Box sx={{ mt: 2, p: 1.5, bgcolor: "rgba(239, 68, 68, 0.1)", borderRadius: 1 }}>
                                      <Typography variant="subtitle2" sx={{ color: "#ef4444" }}>
                                        💥 Real-World Impact:
                                      </Typography>
                                      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                        {chain.real_world_impact}
                                      </Typography>
                                    </Box>
                                  )}
                                </AccordionDetails>
                              </Accordion>
                            ))
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4 }}>
                              <LinkIcon sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
                              <Typography color="text.secondary">No attack chains identified</Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Remediation Tab */}
                      {aiAnalysisTab === 2 && (
                        <Box>
                          {zapAiAnalysis.remediation_plan && zapAiAnalysis.remediation_plan.length > 0 ? (
                            zapAiAnalysis.remediation_plan.map((item, index) => (
                              <Card 
                                key={index}
                                sx={{ 
                                  mb: 2, 
                                  bgcolor: "rgba(16, 185, 129, 0.05)",
                                  border: "1px solid rgba(16, 185, 129, 0.2)",
                                  borderLeft: item.quick_win ? "4px solid #10b981" : "4px solid rgba(16, 185, 129, 0.3)",
                                }}
                              >
                                <CardContent>
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                                    <Chip
                                      label={`#${item.priority}`}
                                      size="small"
                                      sx={{ bgcolor: "rgba(16, 185, 129, 0.2)", color: "#10b981", fontWeight: 700 }}
                                    />
                                    <Typography variant="subtitle1" sx={{ color: "#fff", fontWeight: 600, flex: 1 }}>
                                      {item.vulnerability}
                                    </Typography>
                                    <Chip
                                      label={item.severity?.toUpperCase()}
                                      size="small"
                                      sx={{
                                        bgcolor: item.severity === "critical" ? "rgba(239, 68, 68, 0.2)" :
                                                 item.severity === "high" ? "rgba(249, 115, 22, 0.2)" :
                                                 item.severity === "medium" ? "rgba(245, 158, 11, 0.2)" :
                                                 "rgba(16, 185, 129, 0.2)",
                                        color: item.severity === "critical" ? "#ef4444" :
                                               item.severity === "high" ? "#f97316" :
                                               item.severity === "medium" ? "#f59e0b" :
                                               "#10b981",
                                      }}
                                    />
                                    <Chip
                                      label={`Effort: ${item.effort}`}
                                      size="small"
                                      variant="outlined"
                                      sx={{ borderColor: "rgba(255,255,255,0.3)", color: "rgba(255,255,255,0.7)" }}
                                    />
                                    {item.quick_win && (
                                      <Chip
                                        icon={<LightbulbIcon />}
                                        label="Quick Win"
                                        size="small"
                                        sx={{ bgcolor: "rgba(16, 185, 129, 0.3)", color: "#10b981" }}
                                      />
                                    )}
                                  </Box>
                                  
                                  <Box 
                                    sx={{ 
                                      color: "rgba(255,255,255,0.8)",
                                      "& h1, & h2, & h3, & h4": { color: "#10b981", fontSize: "0.9rem", mt: 1.5, mb: 0.5 },
                                      "& code": { bgcolor: "rgba(0,0,0,0.3)", px: 0.5, borderRadius: 0.5 },
                                      "& pre": { bgcolor: "rgba(0,0,0,0.4)", p: 1.5, borderRadius: 1, overflow: "auto", fontSize: "0.85rem" },
                                      "& ul, & ol": { pl: 2 },
                                    }}
                                  >
                                    <ReactMarkdown>{item.recommendation}</ReactMarkdown>
                                  </Box>
                                  
                                  {item.affected_count && item.affected_count > 1 && (
                                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)", display: "block", mt: 1 }}>
                                      📍 Affects {item.affected_count} endpoints
                                    </Typography>
                                  )}
                                </CardContent>
                              </Card>
                            ))
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4 }}>
                              <BuildIcon sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
                              <Typography color="text.secondary">No remediation plan generated</Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Attack Narrative Tab */}
                      {aiAnalysisTab === 3 && (
                        <Box 
                          sx={{ 
                            color: "rgba(255,255,255,0.9)",
                            "& h1, & h2, & h3, & h4": { color: "#ef4444", mt: 2, mb: 1 },
                            "& strong": { color: "#f97316" },
                            "& ul, & ol": { pl: 3 },
                            "& li": { mb: 0.5 },
                            "& code": { bgcolor: "rgba(0,0,0,0.3)", px: 1, py: 0.5, borderRadius: 1 },
                            "& pre": { bgcolor: "rgba(0,0,0,0.4)", p: 2, borderRadius: 1, overflow: "auto" },
                          }}
                        >
                          {zapAiAnalysis.attack_narrative ? (
                            <ReactMarkdown>{zapAiAnalysis.attack_narrative}</ReactMarkdown>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4 }}>
                              <TimelineIcon sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
                              <Typography color="text.secondary">Attack narrative not available</Typography>
                              <Typography variant="caption" color="text.secondary">
                                Run AI analysis with more findings to generate attack scenarios
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Offensive Insights Tab */}
                      {aiAnalysisTab === 4 && (
                        <Box>
                          {zapAiAnalysis.offensive_insights ? (
                            <Grid container spacing={2}>
                              {zapAiAnalysis.offensive_insights.easiest_entry_point && (
                                <Grid item xs={12} md={6}>
                                  <Paper sx={{ p: 2, bgcolor: "rgba(239, 68, 68, 0.1)", border: "1px solid rgba(239, 68, 68, 0.2)" }}>
                                    <Typography variant="subtitle2" sx={{ color: "#ef4444", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                      🎯 Easiest Entry Point
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                      {zapAiAnalysis.offensive_insights.easiest_entry_point}
                                    </Typography>
                                  </Paper>
                                </Grid>
                              )}
                              
                              {zapAiAnalysis.offensive_insights.most_valuable_target && (
                                <Grid item xs={12} md={6}>
                                  <Paper sx={{ p: 2, bgcolor: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.2)" }}>
                                    <Typography variant="subtitle2" sx={{ color: "#f59e0b", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                      💎 Most Valuable Target
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                      {zapAiAnalysis.offensive_insights.most_valuable_target}
                                    </Typography>
                                  </Paper>
                                </Grid>
                              )}
                              
                              {zapAiAnalysis.offensive_insights.estimated_time_to_compromise && (
                                <Grid item xs={12} md={6}>
                                  <Paper sx={{ p: 2, bgcolor: "rgba(139, 92, 246, 0.1)", border: "1px solid rgba(139, 92, 246, 0.2)" }}>
                                    <Typography variant="subtitle2" sx={{ color: "#a78bfa", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                      <AccessTimeIcon fontSize="small" /> Time to Compromise
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                      {zapAiAnalysis.offensive_insights.estimated_time_to_compromise}
                                    </Typography>
                                  </Paper>
                                </Grid>
                              )}
                              
                              {zapAiAnalysis.offensive_insights.required_skill_level && (
                                <Grid item xs={12} md={6}>
                                  <Paper sx={{ p: 2, bgcolor: "rgba(16, 185, 129, 0.1)", border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                                    <Typography variant="subtitle2" sx={{ color: "#10b981", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                      🧑‍💻 Required Skill Level
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                      {zapAiAnalysis.offensive_insights.required_skill_level}
                                    </Typography>
                                  </Paper>
                                </Grid>
                              )}
                              
                              {zapAiAnalysis.offensive_insights.detection_likelihood && (
                                <Grid item xs={12}>
                                  <Paper sx={{ p: 2, bgcolor: "rgba(59, 130, 246, 0.1)", border: "1px solid rgba(59, 130, 246, 0.2)" }}>
                                    <Typography variant="subtitle2" sx={{ color: "#3b82f6", mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                                      👁️ Detection Likelihood
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.8)" }}>
                                      {zapAiAnalysis.offensive_insights.detection_likelihood}
                                    </Typography>
                                  </Paper>
                                </Grid>
                              )}
                            </Grid>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4 }}>
                              <TrendingUpIcon sx={{ fontSize: 48, color: "rgba(255,255,255,0.2)", mb: 1 }} />
                              <Typography color="text.secondary">Offensive insights not available</Typography>
                            </Box>
                          )}
                        </Box>
                      )}
                    </Box>
                  </Box>
                )}
              </Paper>
            </Collapse>

            {zapAiError && (
              <Alert severity="error" onClose={() => setZapAiError(null)} sx={{ mb: 2 }}>
                {zapAiError}
              </Alert>
            )}

            {/* AI Security Chatbot */}
            {zapAlerts.length > 0 && (
              <Paper
                sx={{
                  mt: 3,
                  bgcolor: "rgba(139, 92, 246, 0.03)",
                  border: "1px solid rgba(139, 92, 246, 0.2)",
                  borderRadius: 2,
                  overflow: "hidden",
                }}
              >
                {/* Chat Header */}
                <Box
                  sx={{
                    display: "flex",
                    alignItems: "center",
                    gap: 2,
                    p: 2,
                    bgcolor: "rgba(139, 92, 246, 0.1)",
                    borderBottom: "1px solid rgba(139, 92, 246, 0.2)",
                  }}
                >
                  <Box
                    sx={{
                      width: 36,
                      height: 36,
                      borderRadius: "50%",
                      bgcolor: "rgba(139, 92, 246, 0.2)",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      animation: chatLoading ? `${pulse} 1.5s ease-in-out infinite` : "none",
                    }}
                  >
                    <SmartToyIcon sx={{ color: "#a78bfa", fontSize: 20 }} />
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="subtitle1" sx={{ color: "#a78bfa", fontWeight: 700 }}>
                      🤖 Security Analysis Assistant
                    </Typography>
                    <Typography variant="caption" sx={{ color: "rgba(255,255,255,0.5)" }}>
                      Ask questions about the scan results, vulnerabilities, or remediation strategies
                    </Typography>
                  </Box>
                  <Chip
                    label={`${zapAlerts.length} alerts loaded`}
                    size="small"
                    sx={{ bgcolor: "rgba(16, 185, 129, 0.2)", color: "#10b981" }}
                  />
                </Box>

                {/* Chat Messages */}
                <Box
                  ref={chatContainerRef}
                  sx={{
                    height: 350,
                    overflow: "auto",
                    p: 2,
                    display: "flex",
                    flexDirection: "column",
                    gap: 2,
                  }}
                >
                  {chatMessages.length === 0 ? (
                    <Box sx={{ textAlign: "center", py: 4 }}>
                      <SmartToyIcon sx={{ fontSize: 48, color: "rgba(139, 92, 246, 0.2)", mb: 2 }} />
                      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)", mb: 2 }}>
                        I'm your AI security assistant. Ask me anything about the scan results!
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center" }}>
                        {[
                          "What are the most critical vulnerabilities?",
                          "How can I fix the XSS issues?",
                          "What's the attack surface like?",
                          "Prioritize remediation for me",
                          "Explain the CSRF vulnerability",
                        ].map((suggestion, idx) => (
                          <Chip
                            key={idx}
                            label={suggestion}
                            size="small"
                            onClick={() => {
                              setChatInput(suggestion);
                            }}
                            sx={{
                              cursor: "pointer",
                              bgcolor: "rgba(139, 92, 246, 0.1)",
                              color: "#a78bfa",
                              border: "1px solid rgba(139, 92, 246, 0.3)",
                              "&:hover": {
                                bgcolor: "rgba(139, 92, 246, 0.2)",
                              },
                            }}
                          />
                        ))}
                      </Box>
                    </Box>
                  ) : (
                    chatMessages.map((msg, idx) => (
                      <Box
                        key={idx}
                        sx={{
                          display: "flex",
                          justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                        }}
                      >
                        <Paper
                          sx={{
                            p: 2,
                            maxWidth: "80%",
                            bgcolor: msg.role === "user" 
                              ? "rgba(16, 185, 129, 0.15)" 
                              : "rgba(139, 92, 246, 0.1)",
                            border: `1px solid ${msg.role === "user" ? "rgba(16, 185, 129, 0.3)" : "rgba(139, 92, 246, 0.2)"}`,
                            borderRadius: 2,
                          }}
                        >
                          <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                            {msg.role === "assistant" && (
                              <SmartToyIcon sx={{ color: "#a78bfa", fontSize: 18, mt: 0.3 }} />
                            )}
                            <Box 
                              sx={{ 
                                flex: 1,
                                color: "rgba(255,255,255,0.9)",
                                "& p": { m: 0, mb: 1 },
                                "& p:last-child": { mb: 0 },
                                "& code": { 
                                  bgcolor: "rgba(0,0,0,0.3)", 
                                  px: 0.5, 
                                  py: 0.25, 
                                  borderRadius: 0.5,
                                  fontFamily: "monospace",
                                  fontSize: "0.85em",
                                },
                                "& pre": {
                                  bgcolor: "rgba(0,0,0,0.4)",
                                  p: 1.5,
                                  borderRadius: 1,
                                  overflow: "auto",
                                  fontSize: "0.85em",
                                },
                                "& ul, & ol": { pl: 2, my: 1 },
                                "& li": { mb: 0.5 },
                                "& strong": { color: msg.role === "user" ? "#34d399" : "#a78bfa" },
                              }}
                            >
                              <ReactMarkdown>{msg.content}</ReactMarkdown>
                            </Box>
                          </Box>
                        </Paper>
                      </Box>
                    ))
                  )}
                  {chatLoading && (
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <CircularProgress size={16} sx={{ color: "#a78bfa" }} />
                      <Typography variant="body2" sx={{ color: "rgba(255,255,255,0.5)" }}>
                        Analyzing...
                      </Typography>
                    </Box>
                  )}
                </Box>

                {/* Chat Input */}
                <Box
                  sx={{
                    display: "flex",
                    gap: 1,
                    p: 2,
                    borderTop: "1px solid rgba(139, 92, 246, 0.2)",
                    bgcolor: "rgba(0,0,0,0.2)",
                  }}
                >
                  <TextField
                    fullWidth
                    size="small"
                    value={chatInput}
                    onChange={(e) => setChatInput(e.target.value)}
                    onKeyPress={(e) => e.key === "Enter" && !e.shiftKey && sendChatMessage()}
                    placeholder="Ask about vulnerabilities, attack vectors, or remediation..."
                    disabled={chatLoading}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        bgcolor: "rgba(0,0,0,0.2)",
                        "& fieldset": { borderColor: "rgba(139, 92, 246, 0.3)" },
                        "&:hover fieldset": { borderColor: "rgba(139, 92, 246, 0.5)" },
                        "&.Mui-focused fieldset": { borderColor: "#a78bfa" },
                      },
                      "& .MuiInputBase-input": { color: "rgba(255,255,255,0.9)" },
                    }}
                    InputProps={{
                      endAdornment: chatInput && (
                        <IconButton 
                          size="small" 
                          onClick={() => setChatInput("")}
                          sx={{ color: "rgba(255,255,255,0.3)" }}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      ),
                    }}
                  />
                  <Button
                    variant="contained"
                    onClick={sendChatMessage}
                    disabled={!chatInput.trim() || chatLoading}
                    sx={{
                      bgcolor: "#8b5cf6",
                      minWidth: 100,
                      "&:hover": { bgcolor: "#7c3aed" },
                      "&:disabled": { bgcolor: "rgba(139, 92, 246, 0.3)" },
                    }}
                  >
                    {chatLoading ? <CircularProgress size={20} sx={{ color: "#fff" }} /> : "Send"}
                  </Button>
                </Box>
              </Paper>
            )}

            {/* Empty State */}
            {zapAlerts.length === 0 && (
              <Box 
                sx={{ 
                  textAlign: "center", 
                  py: 10, 
                  color: "text.secondary",
                  position: "relative",
                }}
              >
                <Box
                  sx={{
                    position: "relative",
                    display: "inline-block",
                    animation: `${float} 4s ease-in-out infinite`,
                  }}
                >
                  <RadarIcon sx={{ fontSize: 80, mb: 2, color: "rgba(16, 185, 129, 0.2)" }} />
                  <Box
                    sx={{
                      position: "absolute",
                      top: "50%",
                      left: "50%",
                      transform: "translate(-50%, -50%)",
                      width: 100,
                      height: 100,
                      border: "2px solid rgba(16, 185, 129, 0.2)",
                      borderRadius: "50%",
                      borderTopColor: "rgba(16, 185, 129, 0.5)",
                      animation: `${radarSweep} 3s linear infinite`,
                    }}
                  />
                </Box>
                <Typography variant="h6" sx={{ color: "#10b981", mb: 1 }}>No alerts yet</Typography>
                <Typography variant="body2" color="text.secondary">
                  Start a scan or select a saved scan to view results
                </Typography>
                {beginnerMode && (
                  <Box sx={{ mt: 3, p: 2, bgcolor: "rgba(245, 158, 11, 0.1)", borderRadius: 2, display: "inline-block" }}>
                    <Typography variant="body2" sx={{ color: "#f59e0b" }}>
                      💡 <strong>Tip:</strong> Enter a URL on the left and click "Start Scan" to begin!
                    </Typography>
                  </Box>
                )}
              </Box>
            )}
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};

export default ZAPPage;
