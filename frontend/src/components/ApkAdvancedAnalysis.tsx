/**
 * Advanced APK Analysis Components
 * 
 * Features:
 * - JADX Java Decompilation with Source Viewer
 * - Manifest Visualization with Mermaid Diagrams (rendered inline)
 * - Attack Surface Map with Exploitation Guidance
 */

import React, { useState, useEffect, useCallback } from "react";
import { MermaidDiagram } from "./MermaidDiagram";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Chip,
  IconButton,
  Tooltip,
  alpha,
  useTheme,
  Divider,
  TextField,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Card,
  CardContent,
  LinearProgress,
  InputAdornment,
  Collapse,
  Badge,
  Switch,
  FormControlLabel,
} from "@mui/material";
import {
  Code as CodeIcon,
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Folder as FolderIcon,
  Description as FileIcon,
  Android as ApkIcon,
  ContentCopy as CopyIcon,
  PlayArrow as PlayIcon,
  BugReport as BugIcon,
  AccountTree as TreeIcon,
  Shield as ShieldIcon,
  Link as LinkIcon,
  Terminal as TerminalIcon,
  Visibility as ViewIcon,
  ExpandLess as CollapseIcon,
  Layers as LayersIcon,
  Public as ExportedIcon,
  Lock as PrivateIcon,
  NavigateNext as ArrowIcon,
} from "@mui/icons-material";
import {
  reverseEngineeringClient,
  type JadxDecompilationResult,
  type JadxSourceResult,
  type JadxSearchResult,
  type ManifestVisualizationResult,
  type ManifestNode,
  type AttackSurfaceMapResult,
  type AttackVector,
  type DeepLinkEntry,
  type ObfuscationAnalysisResult,
  type ObfuscationIndicator,
  type StringEncryptionPattern,
  type AICodeExplanationResult,
  type AIVulnerabilityAnalysisResult,
  type ClassDataFlowResult,
  type CallGraphResult,
  type SmartSearchResult,
  type SmartSearchMatch,
  type AIVulnScanResult,
  type EnhancedSecurityResult,
  type EnhancedSecurityFinding,
  type SmaliViewResult,
  type StringExtractionResult,
  type CrossReferenceResult,
  type ProjectZipInfo,
  type PermissionAnalysisResult,
  type NetworkEndpointResult,
  type CryptoAuditResult,
  type ComponentMapResult,
  type SymbolLookupResult,
  type DependencyGraphResult,
} from "../api/client";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import PsychologyIcon from "@mui/icons-material/Psychology";
import GppMaybeIcon from "@mui/icons-material/GppMaybe";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import TimelineIcon from "@mui/icons-material/Timeline";
import RadarIcon from "@mui/icons-material/Radar";
import ManageSearchIcon from "@mui/icons-material/ManageSearch";
import Select from "@mui/material/Select";
import MenuItem from "@mui/material/MenuItem";
import Menu from "@mui/material/Menu";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import DataArrayIcon from "@mui/icons-material/DataArray";
import TextSnippetIcon from "@mui/icons-material/TextSnippet";
import HubIcon from "@mui/icons-material/Hub";
import DownloadIcon from "@mui/icons-material/Download";
import WifiIcon from "@mui/icons-material/Wifi";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import EnhancedEncryptionIcon from "@mui/icons-material/EnhancedEncryption";
import MapIcon from "@mui/icons-material/Map";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";

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
    default:
      return "#6b7280";
  }
};

// ============================================================================
// JADX Java Decompiler Component
// ============================================================================

interface JadxDecompilerProps {
  apkFile: File | null;
  onDecompilationComplete?: (result: JadxDecompilationResult) => void;
  /** @deprecated Security scan moved to Security Findings tab in main APK results */
  onEnhancedSecurityComplete?: (result: EnhancedSecurityResult) => void;
  /** If provided, skip decompilation and use this existing session */
  initialSessionId?: string;
  /** Source tree from unified scan - if provided, use it instead of empty tree */
  initialSourceTree?: Record<string, unknown>;
  /** Total classes from unified scan */
  initialTotalClasses?: number;
  /** Total files from unified scan */
  initialTotalFiles?: number;
}

export function JadxDecompiler({ apkFile, onDecompilationComplete, initialSessionId, initialSourceTree, initialTotalClasses, initialTotalFiles }: JadxDecompilerProps) {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<JadxDecompilationResult | null>(null);
  const [selectedClass, setSelectedClass] = useState<string | null>(null);
  const [sourceCode, setSourceCode] = useState<JadxSourceResult | null>(null);
  const [sourceLoading, setSourceLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<JadxSearchResult | null>(null);
  const [searchLoading, setSearchLoading] = useState(false);
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  
  // AI Analysis State
  const [aiExplanation, setAiExplanation] = useState<AICodeExplanationResult | null>(null);
  const [aiVulnerabilities, setAiVulnerabilities] = useState<AIVulnerabilityAnalysisResult | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiTab, setAiTab] = useState(0); // 0 = source, 1 = explain, 2 = vulnerabilities, 3 = dataflow, 4 = callgraph
  
  // Data Flow & Call Graph State
  const [dataFlow, setDataFlow] = useState<ClassDataFlowResult | null>(null);
  const [callGraph, setCallGraph] = useState<CallGraphResult | null>(null);
  const [dataFlowLoading, setDataFlowLoading] = useState(false);
  const [callGraphLoading, setCallGraphLoading] = useState(false);
  
  // Smart Search State
  const [smartSearchQuery, setSmartSearchQuery] = useState("");
  const [smartSearchType, setSmartSearchType] = useState<"smart" | "vuln" | "regex" | "exact">("smart");
  const [smartSearchResult, setSmartSearchResult] = useState<SmartSearchResult | null>(null);
  const [smartSearchLoading, setSmartSearchLoading] = useState(false);
  
  // AI Full Vulnerability Scan State
  const [aiVulnScanResult, setAiVulnScanResult] = useState<AIVulnScanResult | null>(null);
  const [aiVulnScanLoading, setAiVulnScanLoading] = useState(false);
  const [aiVulnScanType, setAiVulnScanType] = useState<"quick" | "deep" | "focused">("quick");
  
  // Smali View State
  const [smaliView, setSmaliView] = useState<SmaliViewResult | null>(null);
  const [smaliLoading, setSmaliLoading] = useState(false);
  const [showSmali, setShowSmali] = useState(false);
  
  // String Extraction State
  const [extractedStrings, setExtractedStrings] = useState<StringExtractionResult | null>(null);
  const [stringsLoading, setStringsLoading] = useState(false);
  const [stringFilter, setStringFilter] = useState<string[]>([]);
  
  // Cross-Reference State
  const [crossRefs, setCrossRefs] = useState<CrossReferenceResult | null>(null);
  const [xrefLoading, setXrefLoading] = useState(false);

  // Project ZIP State
  const [zipInfo, setZipInfo] = useState<ProjectZipInfo | null>(null);
  const [zipLoading, setZipLoading] = useState(false);
  const [downloadingZip, setDownloadingZip] = useState(false);

  // Permission Analysis State
  const [permissions, setPermissions] = useState<PermissionAnalysisResult | null>(null);
  const [permissionsLoading, setPermissionsLoading] = useState(false);

  // Network Endpoints State
  const [networkEndpoints, setNetworkEndpoints] = useState<NetworkEndpointResult | null>(null);
  const [networkLoading, setNetworkLoading] = useState(false);

  // Crypto Audit State
  const [cryptoAudit, setCryptoAudit] = useState<CryptoAuditResult | null>(null);
  const [cryptoLoading, setCryptoLoading] = useState(false);

  // Component Map State
  const [componentMap, setComponentMap] = useState<ComponentMapResult | null>(null);
  const [componentMapLoading, setComponentMapLoading] = useState(false);

  // Symbol Lookup State (Jump to Definition)
  const [symbolLookupResult, setSymbolLookupResult] = useState<SymbolLookupResult | null>(null);
  const [symbolLookupLoading, setSymbolLookupLoading] = useState(false);
  const [symbolQuery, setSymbolQuery] = useState("");

  // Dependency Graph State
  const [dependencyGraph, setDependencyGraph] = useState<DependencyGraphResult | null>(null);
  const [dependencyGraphLoading, setDependencyGraphLoading] = useState(false);

  // Handle pre-existing session from unified scan
  useEffect(() => {
    if (initialSessionId && !result) {
      // Log for debugging
      console.log("[JadxDecompiler] Initializing from unified scan:", {
        sessionId: initialSessionId,
        sourceTreeKeys: initialSourceTree ? Object.keys(initialSourceTree).length : 0,
        totalClasses: initialTotalClasses,
        totalFiles: initialTotalFiles
      });
      
      // We already have a JADX session, create a result using unified scan data
      setResult({
        package_name: "",
        total_classes: initialTotalClasses || 0,
        total_files: initialTotalFiles || 0,
        output_directory: initialSessionId,
        decompilation_time: 0,
        classes: [],
        source_tree: initialSourceTree || {},
        security_issues: [],
        errors: [],
        warnings: [],
      });
    }
  }, [initialSessionId, initialSourceTree, initialTotalClasses, initialTotalFiles, result]);

  const handleDecompile = async () => {
    if (!apkFile) return;
    
    setLoading(true);
    setError(null);
    setResult(null);
    
    try {
      const res = await reverseEngineeringClient.decompileApk(apkFile);
      setResult(res);
      
      // Notify parent component of successful decompilation
      if (onDecompilationComplete) {
        onDecompilationComplete(res);
      }
      
      if (res.errors.length > 0) {
        setError(res.errors.join(", "));
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : "Decompilation failed";
      // Provide more helpful error messages
      if (errorMessage.includes("Failed to fetch") || errorMessage.includes("NetworkError")) {
        setError("Connection error: Unable to reach the server. Please check if the backend is running.");
      } else if (errorMessage.includes("timed out")) {
        setError("Decompilation timed out. Large APKs (>50MB) may take over 5 minutes. Please try again or use a smaller APK.");
      } else {
        setError(errorMessage);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSelectClass = async (classPath: string) => {
    if (!result) return;
    
    setSelectedClass(classPath);
    setSourceLoading(true);
    setSourceCode(null); // Clear previous source immediately
    setAiExplanation(null);
    setAiVulnerabilities(null);
    setDataFlow(null);
    setCallGraph(null);
    setAiTab(0);
    setError(null); // Clear previous errors
    
    try {
      console.log("Loading source for:", classPath, "session:", result.output_directory);
      const source = await reverseEngineeringClient.getDecompiledSource(
        result.output_directory,
        classPath
      );
      console.log("Source loaded:", source.class_name, source.line_count, "lines");
      setSourceCode(source);
    } catch (err) {
      console.error("Failed to load source:", err);
      const errorMsg = err instanceof Error ? err.message : "Failed to load source";
      setError(`Failed to load ${classPath}: ${errorMsg}`);
      setSourceCode(null);
    } finally {
      setSourceLoading(false);
    }
  };

  // AI Analysis Handlers
  const handleExplainWithAI = async (type: "general" | "security" = "general") => {
    if (!sourceCode) return;
    
    setAiLoading(true);
    setAiTab(1);
    
    try {
      const explanation = await reverseEngineeringClient.explainCodeWithAI(
        sourceCode.source_code,
        sourceCode.class_name,
        type
      );
      setAiExplanation(explanation);
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI explanation failed");
    } finally {
      setAiLoading(false);
    }
  };

  const handleFindVulnerabilities = async () => {
    if (!sourceCode) return;
    
    setAiLoading(true);
    setAiTab(2);
    
    try {
      const vulns = await reverseEngineeringClient.analyzeVulnerabilitiesWithAI(
        sourceCode.source_code,
        sourceCode.class_name
      );
      setAiVulnerabilities(vulns);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Vulnerability analysis failed");
    } finally {
      setAiLoading(false);
    }
  };

  // Data Flow Analysis Handler
  const handleAnalyzeDataFlow = async () => {
    if (!sourceCode) return;
    
    setDataFlowLoading(true);
    setAiTab(3);
    
    try {
      const flow = await reverseEngineeringClient.analyzeDataFlow(
        sourceCode.source_code,
        sourceCode.class_name
      );
      setDataFlow(flow);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Data flow analysis failed");
    } finally {
      setDataFlowLoading(false);
    }
  };

  // Call Graph Analysis Handler
  const handleBuildCallGraph = async () => {
    if (!sourceCode) return;
    
    setCallGraphLoading(true);
    setAiTab(4);
    
    try {
      const graph = await reverseEngineeringClient.buildCallGraph(
        sourceCode.source_code,
        sourceCode.class_name
      );
      setCallGraph(graph);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Call graph analysis failed");
    } finally {
      setCallGraphLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!result || !searchQuery.trim()) return;
    
    setSearchLoading(true);
    
    try {
      const results = await reverseEngineeringClient.searchDecompiledSources(
        result.output_directory,
        searchQuery
      );
      setSearchResults(results);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setSearchLoading(false);
    }
  };

  // Smart Search Handler
  const handleSmartSearch = async () => {
    if (!result || !smartSearchQuery.trim()) return;
    
    setSmartSearchLoading(true);
    setSmartSearchResult(null);
    
    try {
      const res = await reverseEngineeringClient.smartSearch(
        result.output_directory,
        smartSearchQuery,
        smartSearchType,
        100
      );
      setSmartSearchResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Smart search failed");
    } finally {
      setSmartSearchLoading(false);
    }
  };

  // AI Full Vulnerability Scan Handler
  const handleAiVulnScan = async () => {
    if (!result) return;
    
    setAiVulnScanLoading(true);
    setAiVulnScanResult(null);
    
    try {
      const res = await reverseEngineeringClient.aiVulnScan(
        result.output_directory,
        aiVulnScanType,
        ["authentication", "data_storage", "network", "crypto"]
      );
      setAiVulnScanResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "AI vulnerability scan failed");
    } finally {
      setAiVulnScanLoading(false);
    }
  };

  // Smali View Handler
  const handleGetSmali = async () => {
    if (!result || !selectedClass) return;
    
    setSmaliLoading(true);
    setSmaliView(null);
    
    try {
      const res = await reverseEngineeringClient.getSmaliView(
        result.output_directory,
        selectedClass
      );
      setSmaliView(res);
      setShowSmali(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Smali view failed");
    } finally {
      setSmaliLoading(false);
    }
  };

  // String Extraction Handler
  const handleExtractStrings = async (filters?: string[]) => {
    if (!result) return;
    
    setStringsLoading(true);
    setExtractedStrings(null);
    
    try {
      const res = await reverseEngineeringClient.extractStrings(
        result.output_directory,
        filters && filters.length > 0 ? filters : undefined
      );
      setExtractedStrings(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "String extraction failed");
    } finally {
      setStringsLoading(false);
    }
  };

  // Cross-Reference Handler
  const handleGetCrossRefs = async () => {
    if (!result || !selectedClass) return;
    
    setXrefLoading(true);
    setCrossRefs(null);
    setAiTab(5); // New tab for xrefs
    
    try {
      const res = await reverseEngineeringClient.getCrossReferences(
        result.output_directory,
        selectedClass
      );
      setCrossRefs(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cross-reference analysis failed");
    } finally {
      setXrefLoading(false);
    }
  };

  // Download ZIP Handler
  const handleDownloadZip = async () => {
    if (!result) return;
    
    setDownloadingZip(true);
    
    try {
      const blob = await reverseEngineeringClient.downloadProjectZip(result.output_directory);
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${result.package_name || 'decompiled'}_source.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download ZIP");
    } finally {
      setDownloadingZip(false);
    }
  };

  // Get ZIP Info Handler
  const handleGetZipInfo = async () => {
    if (!result) return;
    
    setZipLoading(true);
    
    try {
      const info = await reverseEngineeringClient.getProjectZipInfo(result.output_directory);
      setZipInfo(info);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get ZIP info");
    } finally {
      setZipLoading(false);
    }
  };

  // Permission Analysis Handler
  const handleAnalyzePermissions = async () => {
    if (!result) return;
    
    setPermissionsLoading(true);
    
    try {
      const res = await reverseEngineeringClient.analyzePermissions(result.output_directory);
      setPermissions(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Permission analysis failed");
    } finally {
      setPermissionsLoading(false);
    }
  };

  // Network Endpoints Handler
  const handleExtractNetworkEndpoints = async () => {
    if (!result) return;
    
    setNetworkLoading(true);
    
    try {
      const res = await reverseEngineeringClient.extractNetworkEndpoints(result.output_directory);
      setNetworkEndpoints(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Network endpoint extraction failed");
    } finally {
      setNetworkLoading(false);
    }
  };

  // Crypto Audit Handler
  const handleCryptoAudit = async () => {
    if (!result) return;
    
    setCryptoLoading(true);
    
    try {
      const res = await reverseEngineeringClient.cryptoAudit(result.output_directory);
      setCryptoAudit(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Crypto audit failed");
    } finally {
      setCryptoLoading(false);
    }
  };

  // Component Map Handler
  const handleComponentMap = async () => {
    if (!result) return;
    
    setComponentMapLoading(true);
    
    try {
      const res = await reverseEngineeringClient.getComponentMap(result.output_directory);
      setComponentMap(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Component map generation failed");
    } finally {
      setComponentMapLoading(false);
    }
  };

  // Symbol Lookup Handler (Jump to Definition)
  const handleSymbolLookup = async (symbol?: string) => {
    if (!result) return;
    
    const querySymbol = symbol || symbolQuery.trim();
    if (!querySymbol) return;
    
    setSymbolLookupLoading(true);
    
    try {
      const res = await reverseEngineeringClient.lookupSymbol(result.output_directory, querySymbol);
      setSymbolLookupResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Symbol lookup failed");
    } finally {
      setSymbolLookupLoading(false);
    }
  };

  // Handle clicking on a symbol in source code for Jump to Definition
  const handleJumpToDefinition = (symbolName: string) => {
    setSymbolQuery(symbolName);
    handleSymbolLookup(symbolName);
  };

  // Dependency Graph Handler
  const handleGenerateDependencyGraph = async () => {
    if (!result) return;
    
    setDependencyGraphLoading(true);
    
    try {
      const res = await reverseEngineeringClient.getDependencyGraph(result.output_directory, 150);
      setDependencyGraph(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Dependency graph generation failed");
    } finally {
      setDependencyGraphLoading(false);
    }
  };

  const toggleFolder = (path: string) => {
    const newExpanded = new Set(expandedFolders);
    if (newExpanded.has(path)) {
      newExpanded.delete(path);
    } else {
      newExpanded.add(path);
    }
    setExpandedFolders(newExpanded);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Render source tree recursively
  const renderTree = (tree: Record<string, unknown>, path: string = ""): React.ReactNode => {
    if (!tree || typeof tree !== 'object') return null;
    
    return Object.entries(tree).map(([key, value]) => {
      const currentPath = path ? `${path}/${key}` : key;
      
      if (key === 'files' && Array.isArray(value)) {
        // Render files
        return value.map((file: string) => (
          <ListItemButton
            key={`${path}/${file}`}
            sx={{ pl: path.split('/').length * 2 }}
            selected={selectedClass === `${path}/${file}`}
            onClick={() => handleSelectClass(`${path}/${file}`)}
          >
            <ListItemIcon sx={{ minWidth: 32 }}>
              <FileIcon fontSize="small" color="primary" />
            </ListItemIcon>
            <ListItemText 
              primary={file}
              primaryTypographyProps={{ 
                variant: "body2",
                fontFamily: "monospace",
                fontSize: "0.8rem"
              }}
            />
          </ListItemButton>
        ));
      }
      
      if (typeof value === 'object' && value !== null) {
        // Render folder
        const isExpanded = expandedFolders.has(currentPath);
        return (
          <Box key={currentPath}>
            <ListItemButton 
              onClick={() => toggleFolder(currentPath)}
              sx={{ pl: path.split('/').filter(Boolean).length * 2 }}
            >
              <ListItemIcon sx={{ minWidth: 32 }}>
                {isExpanded ? <ExpandMoreIcon fontSize="small" /> : <ArrowIcon fontSize="small" />}
              </ListItemIcon>
              <ListItemIcon sx={{ minWidth: 32 }}>
                <FolderIcon fontSize="small" color="warning" />
              </ListItemIcon>
              <ListItemText 
                primary={key}
                primaryTypographyProps={{ 
                  variant: "body2",
                  fontWeight: 500
                }}
              />
            </ListItemButton>
            <Collapse in={isExpanded}>
              {renderTree(value as Record<string, unknown>, currentPath)}
            </Collapse>
          </Box>
        );
      }
      
      return null;
    });
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <CodeIcon color="primary" /> JADX Decompiler
        <Chip label="Java" size="small" color="warning" sx={{ ml: 1 }} />
        <Chip label="Kotlin" size="small" sx={{ bgcolor: "#7F52FF", color: "white" }} />
      </Typography>
      
      {!result && (
        <Box>
          <Alert severity="info" sx={{ mb: 2 }}>
            Decompile APK to readable <strong>Java</strong> or <strong>Kotlin</strong> source code. This allows you to:
            <ul style={{ margin: "8px 0" }}>
              <li>Browse and search decompiled classes (Java & Kotlin)</li>
              <li>Find security issues in code patterns</li>
              <li>AI-powered code analysis and vulnerability detection</li>
              <li>Data flow analysis and call graph visualization</li>
            </ul>
          </Alert>
          
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={20} /> : <CodeIcon />}
            onClick={handleDecompile}
            disabled={!apkFile || loading}
            fullWidth
          >
            {loading ? "Decompiling..." : "Decompile APK (Java/Kotlin)"}
          </Button>
          
          {loading && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress />
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                This may take several minutes for large APKs...
              </Typography>
            </Box>
          )}
        </Box>
      )}

      {error && (
        <Alert severity="warning" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 2 }}>
          {/* Stats */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                <Typography variant="h4" color="primary">{result.total_classes}</Typography>
                <Typography variant="caption" color="text.secondary">Classes</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                <Typography variant="h4" color="success.main">{result.total_files}</Typography>
                <Typography variant="caption" color="text.secondary">Files</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                <Typography variant="h4" color="error">{result.security_issues.length}</Typography>
                <Typography variant="caption" color="text.secondary">Security Issues</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Paper sx={{ p: 2, textAlign: "center" }}>
                <Typography variant="h4">{result.decompilation_time.toFixed(1)}s</Typography>
                <Typography variant="caption" color="text.secondary">Decompile Time</Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Action Buttons - Download, Permissions, Network */}
          <Box sx={{ display: "flex", gap: 1, mb: 3, flexWrap: "wrap" }}>
            <Button
              variant="outlined"
              color="primary"
              startIcon={downloadingZip ? <CircularProgress size={16} /> : <DownloadIcon />}
              onClick={handleDownloadZip}
              disabled={downloadingZip}
              size="small"
            >
              {downloadingZip ? "Preparing..." : "Download Source ZIP"}
            </Button>
            <Button
              variant="outlined"
              color="warning"
              startIcon={permissionsLoading ? <CircularProgress size={16} /> : <VpnKeyIcon />}
              onClick={handleAnalyzePermissions}
              disabled={permissionsLoading}
              size="small"
            >
              {permissionsLoading ? "Analyzing..." : "Analyze Permissions"}
            </Button>
            <Button
              variant="outlined"
              color="secondary"
              startIcon={networkLoading ? <CircularProgress size={16} /> : <WifiIcon />}
              onClick={handleExtractNetworkEndpoints}
              disabled={networkLoading}
              size="small"
            >
              {networkLoading ? "Extracting..." : "Extract Network Endpoints"}
            </Button>
            <Button
              variant="outlined"
              color="error"
              startIcon={cryptoLoading ? <CircularProgress size={16} /> : <EnhancedEncryptionIcon />}
              onClick={handleCryptoAudit}
              disabled={cryptoLoading}
              size="small"
            >
              {cryptoLoading ? "Auditing..." : "Crypto Audit"}
            </Button>
            <Button
              variant="outlined"
              color="info"
              startIcon={componentMapLoading ? <CircularProgress size={16} /> : <MapIcon />}
              onClick={handleComponentMap}
              disabled={componentMapLoading}
              size="small"
            >
              {componentMapLoading ? "Generating..." : "Component Map"}
            </Button>
            <Button
              variant="outlined"
              color="secondary"
              startIcon={dependencyGraphLoading ? <CircularProgress size={16} /> : <HubIcon />}
              onClick={handleGenerateDependencyGraph}
              disabled={dependencyGraphLoading}
              size="small"
            >
              {dependencyGraphLoading ? "Analyzing..." : "Class Network Graph"}
            </Button>
          </Box>

          {/* Permission Analysis Results */}
          {permissions && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.warning.main, 0.05), border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <VpnKeyIcon color="warning" />
                  <Typography variant="subtitle2" color="warning.main">Permission Analysis</Typography>
                  <Chip 
                    label={`${permissions.overall_risk.toUpperCase()} RISK`}
                    size="small"
                    sx={{ 
                      bgcolor: getSeverityColor(permissions.overall_risk),
                      color: "white",
                      fontWeight: 700
                    }}
                  />
                </Box>
                <Chip 
                  label={`Score: ${permissions.risk_score}/100`}
                  size="small"
                  variant="outlined"
                  color={permissions.risk_score > 50 ? "error" : permissions.risk_score > 25 ? "warning" : "success"}
                />
              </Box>

              {/* Summary */}
              <Typography variant="body2" color="grey.400" sx={{ mb: 2 }}>
                {permissions.summary}
              </Typography>

              {/* Stats */}
              <Grid container spacing={1} sx={{ mb: 2 }}>
                <Grid item xs={3}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                    <Typography variant="h5" color="error">{permissions.by_level.signature?.length || 0}</Typography>
                    <Typography variant="caption">Signature</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={3}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                    <Typography variant="h5" color="warning.main">{permissions.by_level.dangerous?.length || 0}</Typography>
                    <Typography variant="caption">Dangerous</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={3}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                    <Typography variant="h5" color="success.main">{permissions.by_level.normal?.length || 0}</Typography>
                    <Typography variant="caption">Normal</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={3}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.grey[800], 0.3) }}>
                    <Typography variant="h5">{permissions.total_permissions}</Typography>
                    <Typography variant="caption">Total</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* Dangerous Combinations */}
              {permissions.dangerous_combinations.length > 0 && (
                <Accordion defaultExpanded sx={{ mb: 1, bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2" color="error">
                      💀 Dangerous Combinations ({permissions.dangerous_combinations.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {permissions.dangerous_combinations.map((combo, idx) => (
                        <ListItem key={idx} sx={{ mb: 1, bgcolor: alpha(theme.palette.error.main, 0.1), borderRadius: 1 }}>
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={combo.risk.toUpperCase()} 
                                  size="small"
                                  sx={{ 
                                    bgcolor: getSeverityColor(combo.risk),
                                    color: "white",
                                    height: 18,
                                    fontSize: "0.65rem"
                                  }}
                                />
                                <Typography variant="body2" fontWeight={600}>{combo.description}</Typography>
                              </Box>
                            }
                            secondary={
                              <Box sx={{ display: "flex", gap: 0.5, mt: 0.5, flexWrap: "wrap" }}>
                                {combo.permissions.map((p, i) => (
                                  <Chip 
                                    key={i}
                                    label={p.split('.').pop()}
                                    size="small"
                                    variant="outlined"
                                    sx={{ height: 16, fontSize: "0.6rem" }}
                                  />
                                ))}
                              </Box>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Dangerous Permissions */}
              {(permissions.by_level.signature?.length > 0 || permissions.by_level.dangerous?.length > 0) && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2" color="warning.main">
                      ⚠️ Dangerous & Signature Permissions ({(permissions.by_level.signature?.length || 0) + (permissions.by_level.dangerous?.length || 0)})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {[...(permissions.by_level.signature || []), ...(permissions.by_level.dangerous || [])].map((perm, idx) => (
                        <ListItem key={idx} sx={{ py: 0.25 }}>
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={perm.level}
                                  size="small"
                                  color={perm.level === "signature" ? "error" : "warning"}
                                  sx={{ height: 16, fontSize: "0.6rem" }}
                                />
                                <Typography variant="caption" fontFamily="monospace" color="grey.300">
                                  {perm.short_name}
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Typography variant="caption" color="grey.500">
                                {perm.description} ({perm.category})
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* All Permissions by Category */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    📋 All Permissions by Category
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                    {Object.entries(permissions.by_category).map(([cat, perms]) => (
                      <Chip 
                        key={cat}
                        label={`${cat}: ${perms.length}`}
                        size="small"
                        variant="outlined"
                        sx={{ 
                          textTransform: "capitalize",
                          borderColor: cat === "location" || cat === "camera" || cat === "microphone" 
                            ? theme.palette.warning.main 
                            : theme.palette.grey[600]
                        }}
                      />
                    ))}
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Paper>
          )}

          {/* Network Endpoints Results */}
          {networkEndpoints && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.05), border: `1px solid ${alpha(theme.palette.secondary.main, 0.3)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WifiIcon color="secondary" />
                  <Typography variant="subtitle2" color="secondary.main">Network Endpoints</Typography>
                  <Chip label={`${networkEndpoints.total_endpoints} found`} size="small" />
                </Box>
                <Chip 
                  label={`${networkEndpoints.domain_count} domains`}
                  size="small"
                  variant="outlined"
                />
              </Box>

              {/* Summary */}
              <Typography variant="body2" color="grey.400" sx={{ mb: 2 }}>
                {networkEndpoints.summary}
              </Typography>

              {/* Stats */}
              <Grid container spacing={1} sx={{ mb: 2 }}>
                <Grid item xs={4}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                    <Typography variant="h5" color="error">{networkEndpoints.by_risk.high?.length || 0}</Typography>
                    <Typography variant="caption">High Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={4}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                    <Typography variant="h5" color="warning.main">{networkEndpoints.by_risk.medium?.length || 0}</Typography>
                    <Typography variant="caption">Medium Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={4}>
                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                    <Typography variant="h5" color="success.main">{networkEndpoints.by_risk.low?.length || 0}</Typography>
                    <Typography variant="caption">Low Risk</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* High Risk Endpoints */}
              {(networkEndpoints.by_risk.high?.length || 0) > 0 && (
                <Accordion defaultExpanded sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2" color="error">
                      🔴 High-Risk Endpoints ({networkEndpoints.by_risk.high?.length || 0})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {networkEndpoints.by_risk.high?.map((ep, idx) => (
                        <ListItem key={idx} sx={{ bgcolor: alpha(theme.palette.error.main, 0.1), mb: 0.5, borderRadius: 1 }}>
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={ep.category}
                                  size="small"
                                  color="error"
                                  sx={{ height: 18, fontSize: "0.65rem" }}
                                />
                                <Typography 
                                  variant="caption" 
                                  fontFamily="monospace"
                                  sx={{ 
                                    wordBreak: "break-all",
                                    bgcolor: alpha(theme.palette.error.main, 0.2),
                                    p: 0.5,
                                    borderRadius: 0.5
                                  }}
                                >
                                  {ep.value.length > 80 ? ep.value.substring(0, 80) + "..." : ep.value}
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Typography variant="caption" color="text.secondary">
                                {ep.file.split('/').pop()} @ line {ep.line}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Unique Domains */}
              {networkEndpoints.unique_domains.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      🌐 Unique Domains ({networkEndpoints.unique_domains.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap" }}>
                      {networkEndpoints.unique_domains.map((domain, idx) => (
                        <Chip 
                          key={idx}
                          label={domain}
                          size="small"
                          variant="outlined"
                          sx={{ fontFamily: "monospace", fontSize: "0.7rem" }}
                        />
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* All Endpoints by Category */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    📡 All Endpoints ({networkEndpoints.total_endpoints})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {networkEndpoints.endpoints.slice(0, 100).map((ep, idx) => (
                      <ListItem 
                        key={idx}
                        sx={{ 
                          bgcolor: ep.risk === "high" 
                            ? alpha(theme.palette.error.main, 0.05)
                            : ep.risk === "medium"
                              ? alpha(theme.palette.warning.main, 0.05)
                              : alpha(theme.palette.grey[800], 0.2),
                          mb: 0.5,
                          borderRadius: 1
                        }}
                      >
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Chip 
                                label={ep.category}
                                size="small"
                                variant="outlined"
                                sx={{ height: 16, fontSize: "0.6rem" }}
                              />
                              <Typography variant="caption" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                                {ep.value.length > 70 ? ep.value.substring(0, 70) + "..." : ep.value}
                              </Typography>
                            </Box>
                          }
                          secondary={
                            <Typography variant="caption" color="grey.600">
                              {ep.file.split('/').pop()} : {ep.line}
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                    {networkEndpoints.endpoints.length > 100 && (
                      <Typography variant="caption" color="grey.500" sx={{ p: 1 }}>
                        + {networkEndpoints.endpoints.length - 100} more endpoints...
                      </Typography>
                    )}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Paper>
          )}

          {/* Crypto Audit Results */}
          {cryptoAudit && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.error.main, 0.03), border: `1px solid ${alpha(theme.palette.error.main, 0.15)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <EnhancedEncryptionIcon color="error" />
                  <Typography variant="subtitle2" color="error.main">Crypto Audit Results</Typography>
                </Box>
                <Box sx={{ display: "flex", gap: 1 }}>
                  <Chip 
                    label={`Grade: ${cryptoAudit.grade}`}
                    size="small"
                    color={
                      cryptoAudit.grade === "A" ? "success" :
                      cryptoAudit.grade === "B" ? "info" :
                      cryptoAudit.grade === "C" ? "warning" : "error"
                    }
                    sx={{ fontWeight: "bold" }}
                  />
                  <Chip 
                    label={`Risk Score: ${cryptoAudit.risk_score}/100`}
                    size="small"
                    color={cryptoAudit.risk_score > 70 ? "error" : cryptoAudit.risk_score > 40 ? "warning" : "success"}
                    variant="outlined"
                  />
                </Box>
              </Box>

              {/* Summary Stats */}
              <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                <Chip label={`Critical: ${cryptoAudit.by_severity?.critical?.length || 0}`} size="small" color="error" variant={(cryptoAudit.by_severity?.critical?.length || 0) > 0 ? "filled" : "outlined"} />
                <Chip label={`High: ${cryptoAudit.by_severity?.high?.length || 0}`} size="small" color="error" variant={(cryptoAudit.by_severity?.high?.length || 0) > 0 ? "filled" : "outlined"} />
                <Chip label={`Medium: ${cryptoAudit.by_severity?.medium?.length || 0}`} size="small" color="warning" variant={(cryptoAudit.by_severity?.medium?.length || 0) > 0 ? "filled" : "outlined"} />
                <Chip label={`Low: ${cryptoAudit.by_severity?.low?.length || 0}`} size="small" color="info" variant={(cryptoAudit.by_severity?.low?.length || 0) > 0 ? "filled" : "outlined"} />
              </Box>

              {/* Findings by Category */}
              {Object.entries(cryptoAudit.by_category || {}).filter(([, findings]) => findings.length > 0).map(([category, findings]) => (
                <Accordion key={category} sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      {category === "weak_algorithms" && "⚠️ Weak Algorithms"}
                      {category === "ecb_mode" && "🔓 ECB Mode Usage"}
                      {category === "hardcoded_keys" && "🔑 Hardcoded Keys/IVs"}
                      {category === "insecure_random" && "🎲 Insecure Random"}
                      {category === "weak_key_derivation" && "🔐 Weak Key Derivation"}
                      {category === "certificate_bypass" && "📜 Certificate Bypass"}
                      {!["weak_algorithms", "ecb_mode", "hardcoded_keys", "insecure_random", "weak_key_derivation", "certificate_bypass"].includes(category) && `📁 ${category}`}
                      {" "}({findings.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {findings.map((finding: { severity: string; file: string; line: number; description: string; recommendation: string; match: string }, idx: number) => (
                        <ListItem 
                          key={idx}
                          sx={{ 
                            bgcolor: finding.severity === "critical" ? alpha(theme.palette.error.main, 0.1) :
                                     finding.severity === "high" ? alpha(theme.palette.error.main, 0.05) :
                                     finding.severity === "medium" ? alpha(theme.palette.warning.main, 0.05) :
                                     alpha(theme.palette.grey[800], 0.1),
                            mb: 0.5,
                            borderRadius: 1,
                            cursor: "pointer"
                          }}
                          onClick={() => finding.line && handleJumpToDefinition(`${finding.file}:${finding.line}`)}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={finding.severity.toUpperCase()}
                                  size="small"
                                  color={finding.severity === "critical" || finding.severity === "high" ? "error" : finding.severity === "medium" ? "warning" : "info"}
                                  sx={{ height: 16, fontSize: "0.6rem" }}
                                />
                                <Typography variant="caption" fontFamily="monospace">
                                  {finding.description}
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Box>
                                <Typography variant="caption" color="grey.600" display="block">
                                  📄 {finding.file.split('/').pop()}:{finding.line}
                                </Typography>
                                {finding.recommendation && (
                                  <Typography variant="caption" color="success.main" display="block">
                                    💡 {finding.recommendation}
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              ))}

              {/* Good Practices */}
              {cryptoAudit.good_practices.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2" color="success.main">
                      ✅ Good Practices Found ({cryptoAudit.good_practices.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {cryptoAudit.good_practices.map((practice, idx) => (
                        <ListItem key={idx} sx={{ bgcolor: alpha(theme.palette.success.main, 0.05), mb: 0.5, borderRadius: 1 }}>
                          <ListItemText
                            primary={<Typography variant="caption" fontFamily="monospace">{practice.type}: {practice.match}</Typography>}
                            secondary={<Typography variant="caption" color="grey.600">📄 {practice.file.split('/').pop()}:{practice.line}</Typography>}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}

          {/* Component Map Results */}
          {componentMap && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.info.main, 0.03), border: `1px solid ${alpha(theme.palette.info.main, 0.15)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <MapIcon color="info" />
                  <Typography variant="subtitle2" color="info.main">Activity/Service Map</Typography>
                </Box>
                <Chip 
                  label={`Attack Surface: ${componentMap.attack_surface_score}/100`}
                  size="small"
                  color={componentMap.attack_surface_score > 70 ? "error" : componentMap.attack_surface_score > 40 ? "warning" : "success"}
                  sx={{ fontWeight: "bold" }}
                />
              </Box>

              {/* Package Info */}
              <Typography variant="caption" color="grey.500" display="block" mb={1}>
                📦 Package: {componentMap.package_name}
              </Typography>

              {/* Component Summary */}
              <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                <Chip label={`Activities: ${componentMap.components.activities.length} (${componentMap.components.activities.filter(a => a.exported).length} exported)`} size="small" color="primary" variant="outlined" />
                <Chip label={`Services: ${componentMap.components.services.length} (${componentMap.components.services.filter(s => s.exported).length} exported)`} size="small" color="secondary" variant="outlined" />
                <Chip label={`Receivers: ${componentMap.components.receivers.length} (${componentMap.components.receivers.filter(r => r.exported).length} exported)`} size="small" color="info" variant="outlined" />
                <Chip label={`Providers: ${componentMap.components.providers.length} (${componentMap.components.providers.filter(p => p.exported).length} exported)`} size="small" color="warning" variant="outlined" />
              </Box>

              {/* Deep Links */}
              {componentMap.deep_links.length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2" color="warning.main">
                      🔗 Deep Links ({componentMap.deep_links.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {componentMap.deep_links.map((link, idx) => (
                        <ListItem key={idx} sx={{ bgcolor: alpha(theme.palette.warning.main, 0.05), mb: 0.5, borderRadius: 1 }}>
                          <ListItemText
                            primary={<Typography variant="caption" fontFamily="monospace">{link.scheme}://{link.host}{link.path || "/*"}</Typography>}
                            secondary={<Typography variant="caption" color="grey.600">→ {link.component}</Typography>}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Activities */}
              {componentMap.components.activities.length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      📱 Activities ({componentMap.components.activities.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {componentMap.components.activities.map((activity, idx) => (
                        <ListItem 
                          key={idx} 
                          sx={{ 
                            bgcolor: activity.exported ? alpha(theme.palette.warning.main, 0.08) : alpha(theme.palette.grey[800], 0.1),
                            mb: 0.5, 
                            borderRadius: 1,
                            cursor: "pointer"
                          }}
                          onClick={() => handleJumpToDefinition(activity.name.split('.').pop() || activity.name)}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {activity.exported && <Chip label="EXPORTED" size="small" color="warning" sx={{ height: 16, fontSize: "0.55rem" }} />}
                                {activity.launcher && <Chip label="LAUNCHER" size="small" color="primary" sx={{ height: 16, fontSize: "0.55rem" }} />}
                                <Typography variant="caption" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                                  {activity.name.split('.').pop()}
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Typography variant="caption" color="grey.600" sx={{ wordBreak: "break-all" }}>
                                {activity.name}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Services */}
              {componentMap.components.services.length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      ⚙️ Services ({componentMap.components.services.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {componentMap.components.services.map((service, idx) => (
                        <ListItem 
                          key={idx} 
                          sx={{ 
                            bgcolor: service.exported ? alpha(theme.palette.warning.main, 0.08) : alpha(theme.palette.grey[800], 0.1),
                            mb: 0.5, 
                            borderRadius: 1,
                            cursor: "pointer"
                          }}
                          onClick={() => handleJumpToDefinition(service.name.split('.').pop() || service.name)}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {service.exported && <Chip label="EXPORTED" size="small" color="warning" sx={{ height: 16, fontSize: "0.55rem" }} />}
                                <Typography variant="caption" fontFamily="monospace">
                                  {service.name.split('.').pop()}
                                </Typography>
                              </Box>
                            }
                            secondary={service.permission && (
                              <Typography variant="caption" color="grey.600">
                                🔐 {service.permission}
                              </Typography>
                            )}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Receivers */}
              {componentMap.components.receivers.length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      📡 Broadcast Receivers ({componentMap.components.receivers.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {componentMap.components.receivers.map((receiver, idx) => (
                        <ListItem 
                          key={idx} 
                          sx={{ 
                            bgcolor: receiver.exported ? alpha(theme.palette.warning.main, 0.08) : alpha(theme.palette.grey[800], 0.1),
                            mb: 0.5, 
                            borderRadius: 1,
                            cursor: "pointer"
                          }}
                          onClick={() => handleJumpToDefinition(receiver.name.split('.').pop() || receiver.name)}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {receiver.exported && <Chip label="EXPORTED" size="small" color="warning" sx={{ height: 16, fontSize: "0.55rem" }} />}
                                <Typography variant="caption" fontFamily="monospace">
                                  {receiver.name.split('.').pop()}
                                </Typography>
                              </Box>
                            }
                            secondary={receiver.actions.length > 0 && (
                              <Typography variant="caption" color="grey.600">
                                Actions: {receiver.actions.slice(0, 2).join(", ")}{receiver.actions.length > 2 ? "..." : ""}
                              </Typography>
                            )}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Content Providers */}
              {componentMap.components.providers.length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      💾 Content Providers ({componentMap.components.providers.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {componentMap.components.providers.map((provider, idx) => (
                        <ListItem 
                          key={idx} 
                          sx={{ 
                            bgcolor: provider.exported ? alpha(theme.palette.warning.main, 0.08) : alpha(theme.palette.grey[800], 0.1),
                            mb: 0.5, 
                            borderRadius: 1,
                            cursor: "pointer"
                          }}
                          onClick={() => handleJumpToDefinition(provider.name.split('.').pop() || provider.name)}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                {provider.exported && <Chip label="EXPORTED" size="small" color="warning" sx={{ height: 16, fontSize: "0.55rem" }} />}
                                <Typography variant="caption" fontFamily="monospace">
                                  {provider.name.split('.').pop()}
                                </Typography>
                              </Box>
                            }
                            secondary={provider.authorities && (
                              <Typography variant="caption" color="grey.600">
                                Authority: {provider.authorities}
                              </Typography>
                            )}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Inter-component Connections */}
              {componentMap.connections.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      🔀 Inter-Component Connections ({componentMap.connections.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 200, overflow: "auto" }}>
                      {componentMap.connections.map((conn, idx) => (
                        <ListItem key={idx} sx={{ bgcolor: alpha(theme.palette.grey[800], 0.1), mb: 0.5, borderRadius: 1 }}>
                          <ListItemText
                            primary={
                              <Typography variant="caption" fontFamily="monospace">
                                {conn.source.split('.').pop()} → {conn.target.split('.').pop()}
                              </Typography>
                            }
                            secondary={
                              <Typography variant="caption" color="grey.600">
                                Type: {conn.type}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}

          {/* Class Dependency Graph / Network View */}
          {dependencyGraph && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.03), border: `1px solid ${alpha(theme.palette.secondary.main, 0.15)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <HubIcon color="secondary" />
                  <Typography variant="subtitle2" color="secondary.main">Class Network Graph</Typography>
                </Box>
                <Box sx={{ display: "flex", gap: 1 }}>
                  <Chip label={`${dependencyGraph.statistics.total_classes} Classes`} size="small" color="secondary" variant="outlined" />
                  <Chip label={`${dependencyGraph.statistics.total_connections} Connections`} size="small" variant="outlined" />
                </Box>
              </Box>

              {/* Statistics Overview */}
              <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap" }}>
                {Object.entries(dependencyGraph.statistics.node_types).map(([type, count]) => (
                  <Chip
                    key={type}
                    label={`${type}: ${count}`}
                    size="small"
                    sx={{
                      bgcolor: dependencyGraph.legend.node_colors[type] || "#78909C",
                      color: "white",
                      fontWeight: 500,
                    }}
                  />
                ))}
              </Box>

              {/* Edge Type Legend */}
              <Box sx={{ mb: 2, p: 1, bgcolor: alpha(theme.palette.background.default, 0.5), borderRadius: 1 }}>
                <Typography variant="caption" color="grey.500" display="block" mb={0.5}>Connection Types:</Typography>
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap" }}>
                  {Object.entries(dependencyGraph.legend.edge_types).map(([type, description]) => (
                    <Typography key={type} variant="caption" color="grey.400">
                      <strong>{type}:</strong> {description}
                    </Typography>
                  ))}
                </Box>
              </Box>

              {/* Hub Classes - Most Connected */}
              {dependencyGraph.statistics.hub_classes.length > 0 && (
                <Accordion defaultExpanded sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      🌟 Hub Classes (Most Connected)
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {dependencyGraph.statistics.hub_classes.map((hub, idx) => (
                        <ListItem
                          key={idx}
                          sx={{
                            bgcolor: alpha(theme.palette.secondary.main, 0.08 + (0.02 * (10 - idx))),
                            mb: 0.5,
                            borderRadius: 1,
                            cursor: "pointer",
                          }}
                          onClick={() => handleJumpToDefinition(hub.name)}
                        >
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            <Badge badgeContent={hub.connections} color="secondary" max={999}>
                              <HubIcon fontSize="small" color="secondary" />
                            </Badge>
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography variant="body2" fontFamily="monospace">
                                {hub.name}
                              </Typography>
                            }
                            secondary={`${hub.connections} connections`}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* Package Distribution */}
              {Object.keys(dependencyGraph.statistics.packages).length > 0 && (
                <Accordion sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      📦 Package Distribution
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense>
                      {Object.entries(dependencyGraph.statistics.packages).map(([pkg, count], idx) => (
                        <ListItem key={idx} sx={{ py: 0 }}>
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Typography variant="caption" fontFamily="monospace" color="grey.400">
                                  {pkg}
                                </Typography>
                                <Chip label={count} size="small" sx={{ height: 16, fontSize: "0.65rem" }} />
                              </Box>
                            }
                          />
                        </ListItem>
                      ))}
                    </List>
                  </AccordionDetails>
                </Accordion>
              )}

              {/* All Nodes (Classes) */}
              <Accordion sx={{ mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    📋 All Classes ({dependencyGraph.nodes.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dependencyGraph.nodes.map((node, idx) => (
                      <ListItem
                        key={idx}
                        sx={{
                          bgcolor: alpha(node.color, 0.15),
                          mb: 0.5,
                          borderRadius: 1,
                          cursor: "pointer",
                          borderLeft: `3px solid ${node.color}`,
                        }}
                        onClick={() => handleSelectClass(node.file_path)}
                      >
                        <ListItemIcon sx={{ minWidth: 24 }}>
                          <Box
                            sx={{
                              width: 12,
                              height: 12,
                              borderRadius: "50%",
                              bgcolor: node.color,
                            }}
                          />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography variant="caption" fontFamily="monospace">
                              {node.label}
                            </Typography>
                          }
                          secondary={
                            <Typography variant="caption" color="grey.600">
                              {node.type} • {node.methods} methods • {node.lines} lines
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </AccordionDetails>
              </Accordion>

              {/* Connection Details */}
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    🔗 All Connections ({dependencyGraph.edges.length})
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ mb: 1 }}>
                    <Typography variant="caption" color="grey.500">
                      Connection breakdown:
                    </Typography>
                    <Box sx={{ display: "flex", gap: 1, mt: 0.5, flexWrap: "wrap" }}>
                      {Object.entries(dependencyGraph.statistics.edge_types).map(([type, count]) => (
                        <Chip
                          key={type}
                          label={`${type}: ${count}`}
                          size="small"
                          variant="outlined"
                          color={type === "extends" ? "success" : type === "implements" ? "primary" : type === "calls" ? "error" : "default"}
                        />
                      ))}
                    </Box>
                  </Box>
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dependencyGraph.edges.slice(0, 100).map((edge, idx) => (
                      <ListItem
                        key={idx}
                        sx={{
                          bgcolor: alpha(edge.color, 0.1),
                          mb: 0.5,
                          borderRadius: 1,
                        }}
                      >
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Typography
                                variant="caption"
                                fontFamily="monospace"
                                sx={{ cursor: "pointer", color: "primary.main" }}
                                onClick={() => handleJumpToDefinition(edge.from)}
                              >
                                {edge.from}
                              </Typography>
                              <Typography variant="caption" color="grey.500">
                                {edge.type === "extends" ? "extends" : edge.type === "implements" ? "implements" : edge.type === "imports" ? "imports" : "calls"}
                              </Typography>
                              <Typography
                                variant="caption"
                                fontFamily="monospace"
                                sx={{ cursor: "pointer", color: "secondary.main" }}
                                onClick={() => handleJumpToDefinition(edge.to)}
                              >
                                {edge.to}
                              </Typography>
                            </Box>
                          }
                        />
                      </ListItem>
                    ))}
                    {dependencyGraph.edges.length > 100 && (
                      <Typography variant="caption" color="grey.500" sx={{ p: 1 }}>
                        ... and {dependencyGraph.edges.length - 100} more connections
                      </Typography>
                    )}
                  </List>
                </AccordionDetails>
              </Accordion>
            </Paper>
          )}

          {/* Symbol Lookup / Jump to Definition Results */}
          {symbolLookupResult && (
            <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.success.main, 0.03), border: `1px solid ${alpha(theme.palette.success.main, 0.15)}` }}>
              <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <GpsFixedIcon color="success" />
                  <Typography variant="subtitle2" color="success.main">Symbol Lookup Results</Typography>
                </Box>
                <Typography variant="caption" color="grey.500">
                  Query: "{symbolLookupResult.symbol}"
                </Typography>
              </Box>

              {symbolLookupResult.results.length === 0 ? (
                <Typography variant="body2" color="grey.500" textAlign="center" py={2}>
                  No symbols found matching "{symbolLookupResult.symbol}"
                </Typography>
              ) : (
                <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                  {symbolLookupResult.results.map((result, idx) => (
                    <ListItem 
                      key={idx}
                      sx={{ 
                        bgcolor: alpha(theme.palette.success.main, 0.05),
                        mb: 0.5,
                        borderRadius: 1,
                        cursor: "pointer",
                        "&:hover": { bgcolor: alpha(theme.palette.success.main, 0.1) }
                      }}
                      onClick={() => {
                        // Navigate to the file and line
                        if (result.file && result.line) {
                          handleJumpToDefinition(`${result.file}:${result.line}`);
                        }
                      }}
                    >
                      <ListItemText
                        primary={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Chip 
                              label={result.type}
                              size="small"
                              color={result.type === "class" ? "primary" : result.type === "method" ? "secondary" : "default"}
                              sx={{ height: 18, fontSize: "0.6rem" }}
                            />
                            <Typography variant="body2" fontFamily="monospace" fontWeight="bold">
                              {result.name}
                            </Typography>
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="caption" color="grey.600" display="block">
                              📄 {result.file.split('/').pop()}:{result.line}
                            </Typography>
                            {result.signature && (
                              <Typography variant="caption" color="grey.500" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                                {result.signature.length > 80 ? result.signature.substring(0, 80) + "..." : result.signature}
                              </Typography>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              )}
            </Paper>
          )}

          {/* Jump to Definition Search */}
          <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.success.main, 0.03), border: `1px solid ${alpha(theme.palette.success.main, 0.15)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <GpsFixedIcon color="success" fontSize="small" />
              <Typography variant="subtitle2" color="success.main">Jump to Definition</Typography>
            </Box>
            <Box sx={{ display: "flex", gap: 1 }}>
              <TextField
                size="small"
                placeholder="Enter class, method, or field name..."
                value={symbolQuery}
                onChange={(e) => setSymbolQuery(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleSymbolLookup()}
                fullWidth
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <GpsFixedIcon fontSize="small" color="success" />
                    </InputAdornment>
                  ),
                }}
              />
              <Button 
                variant="outlined" 
                color="success"
                onClick={() => handleSymbolLookup()}
                disabled={symbolLookupLoading || !symbolQuery.trim()}
              >
                {symbolLookupLoading ? <CircularProgress size={20} /> : "Find"}
              </Button>
            </Box>
          </Paper>

          {/* Search */}
          <Box sx={{ mb: 2, display: "flex", gap: 1 }}>
            <TextField
              size="small"
              placeholder="Search in decompiled sources..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyPress={(e) => e.key === "Enter" && handleSearch()}
              fullWidth
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" />
                  </InputAdornment>
                ),
              }}
            />
            <Button 
              variant="outlined" 
              onClick={handleSearch}
              disabled={searchLoading || !searchQuery.trim()}
            >
              {searchLoading ? <CircularProgress size={20} /> : "Search"}
            </Button>
          </Box>

          {/* Smart Search */}
          <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
              <ManageSearchIcon color="info" />
              <Typography variant="subtitle2" color="info.main">Smart Security Search</Typography>
            </Box>
            <Box sx={{ display: "flex", gap: 1, mb: 2 }}>
              <TextField
                size="small"
                placeholder="Search for: password, crypto, api key, network, etc..."
                value={smartSearchQuery}
                onChange={(e) => setSmartSearchQuery(e.target.value)}
                onKeyPress={(e) => e.key === "Enter" && handleSmartSearch()}
                fullWidth
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <ManageSearchIcon fontSize="small" color="info" />
                    </InputAdornment>
                  ),
                }}
              />
              <FormControl size="small" sx={{ minWidth: 120 }}>
                <Select
                  value={smartSearchType}
                  onChange={(e) => setSmartSearchType(e.target.value as "smart" | "vuln" | "regex" | "exact")}
                  sx={{ height: 40 }}
                >
                  <MenuItem value="smart">🧠 Smart</MenuItem>
                  <MenuItem value="vuln">🔴 Vulnerabilities</MenuItem>
                  <MenuItem value="regex">📐 Regex</MenuItem>
                  <MenuItem value="exact">✓ Exact</MenuItem>
                </Select>
              </FormControl>
              <Button 
                variant="contained" 
                color="info"
                onClick={handleSmartSearch}
                disabled={smartSearchLoading || !smartSearchQuery.trim()}
              >
                {smartSearchLoading ? <CircularProgress size={20} /> : "Search"}
              </Button>
            </Box>
            
            {/* Smart Search Results */}
            {smartSearchResult && (
              <Box>
                {/* Summary */}
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
                  <Chip 
                    label={`${smartSearchResult.total_matches} matches`} 
                    size="small"
                    color={smartSearchResult.total_matches > 0 ? "warning" : "default"}
                  />
                  <Chip 
                    label={`${smartSearchResult.files_searched} files searched`} 
                    size="small"
                  />
                  {smartSearchResult.expanded_terms.length > 0 && (
                    <Typography variant="caption" color="text.secondary">
                      Also searched: {smartSearchResult.expanded_terms.join(", ")}
                    </Typography>
                  )}
                </Box>

                {/* Vulnerability Summary */}
                {Object.keys(smartSearchResult.vulnerability_summary).length > 0 && (
                  <Box sx={{ mb: 2 }}>
                    <Typography variant="caption" color="error.main" gutterBottom>
                      ⚠️ Potential Vulnerabilities Found:
                    </Typography>
                    <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
                      {Object.entries(smartSearchResult.vulnerability_summary).map(([type, info]) => (
                        <Chip 
                          key={type}
                          label={`${type}: ${info.count}`}
                          size="small"
                          sx={{ 
                            bgcolor: alpha(getSeverityColor(info.severity), 0.2),
                            color: getSeverityColor(info.severity),
                            fontWeight: 600
                          }}
                        />
                      ))}
                    </Box>
                  </Box>
                )}

                {/* Matches */}
                {smartSearchResult.matches.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="body2">
                        Matches ({smartSearchResult.matches.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                        {smartSearchResult.matches.map((match, idx) => (
                          <ListItemButton 
                            key={idx}
                            onClick={() => handleSelectClass(match.file)}
                            sx={{
                              bgcolor: match.vuln_type ? alpha(getSeverityColor(match.severity || "medium"), 0.1) : "transparent",
                              mb: 0.5,
                              borderRadius: 1
                            }}
                          >
                            <ListItemText
                              primary={
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                  {match.vuln_type && (
                                    <Chip 
                                      label={match.vuln_type} 
                                      size="small"
                                      sx={{ 
                                        height: 18, 
                                        fontSize: "0.65rem",
                                        bgcolor: getSeverityColor(match.severity || "medium"),
                                        color: "white"
                                      }}
                                    />
                                  )}
                                  <Typography variant="body2" fontFamily="monospace" fontSize="0.75rem">
                                    {match.file.split('/').pop()} (line {match.line})
                                  </Typography>
                                </Box>
                              }
                              secondary={
                                <Box>
                                  <Typography 
                                    variant="caption" 
                                    component="pre"
                                    sx={{ 
                                      fontFamily: "monospace",
                                      bgcolor: alpha(theme.palette.warning.main, 0.1),
                                      p: 0.5,
                                      borderRadius: 1,
                                      overflow: "hidden",
                                      textOverflow: "ellipsis",
                                      whiteSpace: "nowrap",
                                    }}
                                  >
                                    {match.code.trim()}
                                  </Typography>
                                  {match.description && (
                                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                                      {match.description}
                                    </Typography>
                                  )}
                                </Box>
                              }
                            />
                          </ListItemButton>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Suggestions */}
                {smartSearchResult.suggestions.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="caption" color="text.secondary">
                      💡 Try also: 
                    </Typography>
                    {smartSearchResult.suggestions.map((sug, idx) => (
                      <Chip 
                        key={idx}
                        label={sug}
                        size="small"
                        variant="outlined"
                        onClick={() => { setSmartSearchQuery(sug); }}
                        sx={{ ml: 0.5, cursor: "pointer" }}
                      />
                    ))}
                  </Box>
                )}
              </Box>
            )}
          </Paper>

          {/* String Extraction */}
          <Paper sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.05), border: `1px solid ${alpha(theme.palette.secondary.main, 0.2)}` }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <TextSnippetIcon color="secondary" />
                <Typography variant="subtitle2" color="secondary.main">String Extraction</Typography>
                <Chip label="Secrets, URLs, Keys" size="small" sx={{ height: 20 }} />
              </Box>
              <Button 
                variant="contained" 
                color="secondary"
                size="small"
                onClick={() => handleExtractStrings()}
                disabled={stringsLoading || !result?.output_directory}
                startIcon={stringsLoading ? <CircularProgress size={16} /> : <TextSnippetIcon />}
              >
                Extract All
              </Button>
            </Box>

            {/* Filter Options */}
            <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mb: 2 }}>
              {["url", "api_key", "password", "aws_key", "jwt", "firebase", "email", "ip_address"].map((filter) => (
                <Chip
                  key={filter}
                  label={filter.replace("_", " ")}
                  size="small"
                  variant={stringFilter.includes(filter) ? "filled" : "outlined"}
                  color={stringFilter.includes(filter) ? "secondary" : "default"}
                  onClick={() => {
                    setStringFilter(prev => 
                      prev.includes(filter) 
                        ? prev.filter(f => f !== filter)
                        : [...prev, filter]
                    );
                  }}
                  sx={{ cursor: "pointer", textTransform: "capitalize" }}
                />
              ))}
            </Box>

            {stringsLoading && (
              <Box sx={{ textAlign: "center", py: 3 }}>
                <CircularProgress color="secondary" />
                <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                  Extracting and classifying strings...
                </Typography>
              </Box>
            )}

            {extractedStrings && !stringsLoading && (
              <Box>
                {/* Stats */}
                <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", mb: 2 }}>
                  <Chip 
                    label={`${extractedStrings.total_strings} total strings`} 
                    size="small"
                    color="default"
                  />
                  <Chip 
                    label={`${extractedStrings.severity_counts?.critical || 0} critical`} 
                    size="small"
                    color="error"
                  />
                  <Chip 
                    label={`${extractedStrings.severity_counts?.high || 0} high`} 
                    size="small"
                    color="warning"
                  />
                  <Chip 
                    label={`${extractedStrings.top_categories?.length || 0} categories`} 
                    size="small"
                    color="secondary"
                  />
                </Box>

                {/* Category Breakdown */}
                {extractedStrings.top_categories && extractedStrings.top_categories.length > 0 && (
                  <Box sx={{ mb: 2, p: 1.5, bgcolor: alpha(theme.palette.secondary.main, 0.1), borderRadius: 1 }}>
                    <Typography variant="caption" color="secondary.main" fontWeight={600} gutterBottom>
                      Top Categories:
                    </Typography>
                    <Box sx={{ display: "flex", gap: 0.5, flexWrap: "wrap", mt: 1 }}>
                      {extractedStrings.top_categories.map(([cat, count]) => (
                        <Chip 
                          key={cat}
                          label={`${cat}: ${count}`}
                          size="small"
                          sx={{ 
                            bgcolor: String(cat).includes("key") || String(cat).includes("secret") || String(cat).includes("password") 
                              ? alpha(theme.palette.error.main, 0.2) 
                              : alpha(theme.palette.info.main, 0.2),
                            fontFamily: "monospace",
                            fontSize: "0.7rem"
                          }}
                        />
                      ))}
                    </Box>
                  </Box>
                )}

                {/* High Value Strings (Critical + High Severity) */}
                {extractedStrings.strings.filter(s => s.severity === "critical" || s.severity === "high").length > 0 && (
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="body2" color="error.main">
                        🔑 High-Value Strings ({extractedStrings.strings.filter(s => s.severity === "critical" || s.severity === "high").length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense sx={{ maxHeight: 250, overflow: "auto" }}>
                        {extractedStrings.strings
                          .filter(s => s.severity === "critical" || s.severity === "high")
                          .slice(0, 50)
                          .map((str, idx) => (
                          <ListItem 
                            key={idx}
                            sx={{ 
                              bgcolor: alpha(str.severity === "critical" ? theme.palette.error.main : theme.palette.warning.main, 0.1),
                              mb: 0.5,
                              borderRadius: 1
                            }}
                          >
                            <ListItemText
                              primary={
                                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                  <Chip 
                                    label={str.categories[0] || "unknown"} 
                                    size="small"
                                    color={str.severity === "critical" ? "error" : "warning"}
                                    sx={{ height: 18, fontSize: "0.65rem" }}
                                  />
                                  <Typography 
                                    variant="caption" 
                                    fontFamily="monospace"
                                    sx={{ 
                                      wordBreak: "break-all",
                                      bgcolor: alpha(theme.palette.error.main, 0.2),
                                      p: 0.5,
                                      borderRadius: 0.5
                                    }}
                                  >
                                    {str.value.length > 100 ? str.value.substring(0, 100) + "..." : str.value}
                                  </Typography>
                                </Box>
                              }
                              secondary={
                                <Typography variant="caption" color="text.secondary">
                                  {str.file.split('/').pop()} @ line {str.line} | Severity: {str.severity}
                                </Typography>
                              }
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* All Strings */}
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">
                      📝 All Categorized Strings ({extractedStrings.strings.length})
                    </Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                      {extractedStrings.strings.slice(0, 100).map((str, idx) => (
                        <ListItem 
                          key={idx}
                          sx={{ 
                            bgcolor: str.severity === "critical" || str.severity === "high"
                              ? alpha(theme.palette.error.main, 0.05) 
                              : alpha(theme.palette.grey[800], 0.3),
                            mb: 0.5,
                            borderRadius: 1
                          }}
                        >
                          <ListItemText
                            primary={
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                <Chip 
                                  label={str.categories[0] || "unknown"} 
                                  size="small"
                                  variant="outlined"
                                  sx={{ height: 18, fontSize: "0.6rem" }}
                                />
                                <Typography variant="caption" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                                  {str.value.length > 80 ? str.value.substring(0, 80) + "..." : str.value}
                                </Typography>
                              </Box>
                            }
                            secondary={
                              <Typography variant="caption" color="grey.600">
                                {str.file.split('/').pop()} : {str.line}
                              </Typography>
                            }
                          />
                        </ListItem>
                      ))}
                      {extractedStrings.strings.length > 100 && (
                        <Typography variant="caption" color="grey.500" sx={{ p: 1 }}>
                          + {extractedStrings.strings.length - 100} more strings...
                        </Typography>
                      )}
                    </List>
                  </AccordionDetails>
                </Accordion>
              </Box>
            )}
          </Paper>

          {/* Search Results */}
          {searchResults && searchResults.total_results > 0 && (
            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography>
                  Search Results ({searchResults.total_results} matches for "{searchResults.query}")
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                  {searchResults.results.map((res, idx) => (
                    <ListItemButton 
                      key={idx}
                      onClick={() => handleSelectClass(res.file)}
                    >
                      <ListItemText
                        primary={
                          <Typography variant="body2" fontFamily="monospace">
                            {res.class_name} (line {res.line})
                          </Typography>
                        }
                        secondary={
                          <Typography 
                            variant="caption" 
                            component="pre"
                            sx={{ 
                              overflow: "hidden", 
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                              fontFamily: "monospace",
                              bgcolor: alpha(theme.palette.warning.main, 0.1),
                              p: 0.5,
                              borderRadius: 1,
                            }}
                          >
                            {res.content}
                          </Typography>
                        }
                      />
                    </ListItemButton>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Security Issues */}
          {result.security_issues.length > 0 && (
            <Accordion sx={{ mb: 2 }}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <BugIcon color="error" />
                  <Typography>
                    Security Issues Found ({result.security_issues.length})
                  </Typography>
                </Box>
              </AccordionSummary>
              <AccordionDetails>
                <List dense>
                  {result.security_issues.map((issue, idx) => (
                    <ListItem key={idx}>
                      <ListItemIcon>
                        <Chip
                          label={issue.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                            color: getSeverityColor(issue.severity),
                            fontWeight: 600,
                          }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={`${issue.type} in ${issue.class}`}
                        secondary={
                          <>
                            <Typography variant="caption" component="span">
                              Line {issue.line}: {issue.description}
                            </Typography>
                            <Typography 
                              variant="caption" 
                              component="pre"
                              sx={{ 
                                display: "block",
                                fontFamily: "monospace",
                                fontSize: "0.7rem",
                                bgcolor: alpha(theme.palette.error.main, 0.1),
                                p: 0.5,
                                borderRadius: 1,
                                mt: 0.5,
                              }}
                            >
                              {issue.code_snippet}
                            </Typography>
                          </>
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Source Browser */}
          <Grid container spacing={2}>
            {/* File Tree */}
            <Grid item xs={12} md={4}>
              <Paper sx={{ maxHeight: 600, overflow: "auto", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="subtitle2" sx={{ p: 1, bgcolor: "background.paper", position: "sticky", top: 0 }}>
                  📁 Source Tree
                </Typography>
                <List dense disablePadding>
                  {renderTree(result.source_tree)}
                </List>
              </Paper>
            </Grid>

            {/* Source Code Viewer with AI Analysis */}
            <Grid item xs={12} md={8}>
              <Paper sx={{ minHeight: 600, bgcolor: "#1a1a2e", overflow: "hidden" }}>
                {sourceLoading ? (
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: 600 }}>
                    <CircularProgress />
                  </Box>
                ) : sourceCode ? (
                  <Box sx={{ height: "100%" }}>
                    {/* Header with class info and AI buttons */}
                    <Box sx={{ 
                      display: "flex", 
                      justifyContent: "space-between", 
                      alignItems: "center", 
                      p: 1.5, 
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.2)}`
                    }}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Typography variant="subtitle2" color="grey.300" fontFamily="monospace">
                          {sourceCode.class_name}
                        </Typography>
                        {sourceCode.is_activity && <Chip label="Activity" size="small" color="primary" />}
                        {sourceCode.is_service && <Chip label="Service" size="small" color="secondary" />}
                        {sourceCode.is_receiver && <Chip label="Receiver" size="small" color="warning" />}
                        {sourceCode.is_provider && <Chip label="Provider" size="small" color="error" />}
                      </Box>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <Tooltip title="Explain with AI">
                          <IconButton 
                            size="small" 
                            onClick={() => handleExplainWithAI("general")}
                            disabled={aiLoading}
                            sx={{ color: "primary.main" }}
                          >
                            <AutoAwesomeIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Security Analysis with AI">
                          <IconButton 
                            size="small" 
                            onClick={() => handleExplainWithAI("security")}
                            disabled={aiLoading}
                            sx={{ color: "warning.main" }}
                          >
                            <PsychologyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Find Vulnerabilities">
                          <IconButton 
                            size="small" 
                            onClick={handleFindVulnerabilities}
                            disabled={aiLoading}
                            sx={{ color: "error.main" }}
                          >
                            <GppMaybeIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Data Flow Analysis">
                          <IconButton 
                            size="small" 
                            onClick={handleAnalyzeDataFlow}
                            disabled={dataFlowLoading}
                            sx={{ color: "info.main" }}
                          >
                            <TimelineIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Call Graph">
                          <IconButton 
                            size="small" 
                            onClick={handleBuildCallGraph}
                            disabled={callGraphLoading}
                            sx={{ color: "secondary.main" }}
                          >
                            <AccountTreeIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Cross-References (XREF)">
                          <IconButton 
                            size="small" 
                            onClick={handleGetCrossRefs}
                            disabled={xrefLoading}
                            sx={{ color: "warning.main" }}
                          >
                            <HubIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title={showSmali ? "Show Java" : "Show Smali"}>
                          <IconButton 
                            size="small" 
                            onClick={showSmali ? () => setShowSmali(false) : handleGetSmali}
                            disabled={smaliLoading}
                            sx={{ color: showSmali ? "success.main" : "grey.400" }}
                          >
                            <DataArrayIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Copy source code">
                          <IconButton 
                            size="small" 
                            onClick={() => copyToClipboard(sourceCode.source_code)}
                            sx={{ color: "grey.400" }}
                          >
                            <CopyIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </Box>
                    
                    {/* Tabs for Source / AI Explanation / Vulnerabilities */}
                    <Tabs 
                      value={aiTab} 
                      onChange={(_, v) => setAiTab(v)}
                      sx={{ 
                        bgcolor: alpha(theme.palette.background.paper, 0.1),
                        "& .MuiTab-root": { color: "grey.400", minHeight: 40, py: 0.5 },
                        "& .Mui-selected": { color: "primary.main" }
                      }}
                    >
                      <Tab label="📄 Source Code" />
                      <Tab 
                        label={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <AutoAwesomeIcon fontSize="small" />
                            Explain
                            {aiExplanation && <Chip label="✓" size="small" color="success" sx={{ height: 16, fontSize: "0.6rem" }} />}
                          </Box>
                        } 
                      />
                      <Tab 
                        label={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <GppMaybeIcon fontSize="small" />
                            Vulnerabilities
                            {aiVulnerabilities && (
                              <Chip 
                                label={aiVulnerabilities.vulnerabilities.length} 
                                size="small" 
                                color={aiVulnerabilities.risk_level === "critical" || aiVulnerabilities.risk_level === "high" ? "error" : "warning"} 
                                sx={{ height: 16, fontSize: "0.6rem" }} 
                              />
                            )}
                          </Box>
                        } 
                      />
                      <Tab 
                        label={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <TimelineIcon fontSize="small" />
                            Data Flow
                            {dataFlow && (
                              <Chip 
                                label={dataFlow.summary.potential_leaks} 
                                size="small" 
                                color={dataFlow.summary.risk_level === "critical" || dataFlow.summary.risk_level === "high" ? "error" : "info"} 
                                sx={{ height: 16, fontSize: "0.6rem" }} 
                              />
                            )}
                          </Box>
                        } 
                      />
                      <Tab 
                        label={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <AccountTreeIcon fontSize="small" />
                            Call Graph
                            {callGraph && (
                              <Chip 
                                label={callGraph.statistics.total_methods} 
                                size="small" 
                                color="secondary" 
                                sx={{ height: 16, fontSize: "0.6rem" }} 
                              />
                            )}
                          </Box>
                        } 
                      />
                      <Tab 
                        label={
                          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                            <HubIcon fontSize="small" />
                            XREF
                            {crossRefs && (
                              <Chip 
                                label={crossRefs.statistics.total_incoming_refs} 
                                size="small" 
                                color="warning" 
                                sx={{ height: 16, fontSize: "0.6rem" }} 
                              />
                            )}
                          </Box>
                        } 
                      />
                    </Tabs>

                    {/* Tab Content */}
                    <Box sx={{ p: 2, maxHeight: 480, overflow: "auto" }}>
                      {/* Source Code Tab (with Smali toggle) */}
                      {aiTab === 0 && (
                        <Box>
                          {showSmali && smaliView ? (
                            <Box>
                              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                <Chip label="SMALI" size="small" color="success" />
                                <Typography variant="caption" color="text.secondary">
                                  Dalvik Bytecode • {smaliView.method_count} methods • {smaliView.registers_used} registers
                                </Typography>
                                {smaliView.is_pseudo && (
                                  <Chip label="Pseudo" size="small" variant="outlined" color="warning" />
                                )}
                              </Box>
                              {smaliView.bytecode_stats?.suspicious_ops && Object.values(smaliView.bytecode_stats.suspicious_ops).some(v => v > 0) && (
                                <Alert severity="warning" sx={{ mb: 1, py: 0 }}>
                                  <Typography variant="caption">
                                    ⚠️ Suspicious operations detected: 
                                    {smaliView.bytecode_stats.suspicious_ops.reflection > 0 && ` Reflection(${smaliView.bytecode_stats.suspicious_ops.reflection})`}
                                    {smaliView.bytecode_stats.suspicious_ops.runtime_exec > 0 && ` Runtime.exec(${smaliView.bytecode_stats.suspicious_ops.runtime_exec})`}
                                    {smaliView.bytecode_stats.suspicious_ops.dex_load > 0 && ` DexLoader(${smaliView.bytecode_stats.suspicious_ops.dex_load})`}
                                  </Typography>
                                </Alert>
                              )}
                              <Box
                                component="pre"
                                sx={{
                                  fontSize: "0.75rem",
                                  fontFamily: "monospace",
                                  color: "#a5d6a7",
                                  lineHeight: 1.4,
                                  m: 0,
                                  whiteSpace: "pre-wrap",
                                  wordBreak: "break-word",
                                  bgcolor: alpha(theme.palette.success.main, 0.05),
                                  p: 1,
                                  borderRadius: 1,
                                }}
                              >
                                {smaliView.smali_code}
                              </Box>
                            </Box>
                          ) : smaliLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress color="success" />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                Converting to Smali bytecode...
                              </Typography>
                            </Box>
                          ) : (
                            <Box
                              component="pre"
                              sx={{
                                fontSize: "0.8rem",
                                fontFamily: "monospace",
                                color: "#e0e0e0",
                                lineHeight: 1.5,
                                m: 0,
                                whiteSpace: "pre-wrap",
                                wordBreak: "break-word",
                              }}
                            >
                              {sourceCode.source_code}
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* AI Explanation Tab */}
                      {aiTab === 1 && (
                        <Box>
                          {aiLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                AI is analyzing the code...
                              </Typography>
                            </Box>
                          ) : aiExplanation ? (
                            <Box>
                              <Typography variant="body2" color="grey.300" sx={{ mb: 2, lineHeight: 1.8 }}>
                                {aiExplanation.explanation}
                              </Typography>
                              
                              {aiExplanation.key_points.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" color="primary.main" gutterBottom>
                                    🔑 Key Points
                                  </Typography>
                                  <List dense>
                                    {aiExplanation.key_points.map((point, idx) => (
                                      <ListItem key={idx} sx={{ py: 0.25 }}>
                                        <ListItemText 
                                          primary={point}
                                          primaryTypographyProps={{ variant: "body2", color: "grey.300" }}
                                        />
                                      </ListItem>
                                    ))}
                                  </List>
                                </Box>
                              )}

                              {aiExplanation.security_concerns.length > 0 && (
                                <Box>
                                  <Typography variant="subtitle2" color="warning.main" gutterBottom>
                                    ⚠️ Security Concerns
                                  </Typography>
                                  {aiExplanation.security_concerns.map((concern, idx) => (
                                    <Alert 
                                      key={idx}
                                      severity={concern.severity === "high" || concern.severity === "critical" ? "error" : concern.severity === "medium" ? "warning" : "info"}
                                      sx={{ mb: 1, bgcolor: "transparent", border: 1, borderColor: "divider" }}
                                    >
                                      <Typography variant="body2" fontWeight={600}>{concern.concern}</Typography>
                                      {concern.recommendation && (
                                        <Typography variant="caption" color="text.secondary">
                                          💡 {concern.recommendation}
                                        </Typography>
                                      )}
                                    </Alert>
                                  ))}
                                </Box>
                              )}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4, color: "grey.500" }}>
                              <AutoAwesomeIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                              <Typography variant="body2">
                                Click the <AutoAwesomeIcon fontSize="small" sx={{ verticalAlign: "middle" }} /> button to explain this code with AI
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Vulnerabilities Tab */}
                      {aiTab === 2 && (
                        <Box>
                          {aiLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                AI is scanning for vulnerabilities...
                              </Typography>
                            </Box>
                          ) : aiVulnerabilities ? (
                            <Box>
                              {/* Risk Summary */}
                              <Box sx={{ 
                                display: "flex", 
                                alignItems: "center", 
                                gap: 2, 
                                mb: 2,
                                p: 1.5,
                                borderRadius: 1,
                                bgcolor: alpha(getSeverityColor(aiVulnerabilities.risk_level), 0.15),
                                border: `1px solid ${getSeverityColor(aiVulnerabilities.risk_level)}`
                              }}>
                                <Chip 
                                  label={aiVulnerabilities.risk_level.toUpperCase()} 
                                  sx={{ 
                                    bgcolor: getSeverityColor(aiVulnerabilities.risk_level),
                                    color: "white",
                                    fontWeight: 700
                                  }} 
                                />
                                <Typography variant="body2" color="grey.300">
                                  {aiVulnerabilities.summary}
                                </Typography>
                              </Box>

                              {/* Vulnerabilities List */}
                              {aiVulnerabilities.vulnerabilities.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" color="error.main" gutterBottom>
                                    🔴 Vulnerabilities Found ({aiVulnerabilities.vulnerabilities.length})
                                  </Typography>
                                  {aiVulnerabilities.vulnerabilities.map((vuln, idx) => (
                                    <Accordion 
                                      key={idx} 
                                      sx={{ 
                                        bgcolor: alpha(getSeverityColor(vuln.severity), 0.1),
                                        "&:before": { display: "none" },
                                        mb: 1
                                      }}
                                    >
                                      <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ color: "grey.400" }} />}>
                                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                                          <Chip 
                                            label={vuln.severity} 
                                            size="small"
                                            sx={{ 
                                              bgcolor: getSeverityColor(vuln.severity),
                                              color: "white",
                                              fontSize: "0.65rem",
                                              height: 20
                                            }} 
                                          />
                                          <Typography variant="body2" color="grey.200" fontWeight={600}>
                                            {vuln.title}
                                          </Typography>
                                        </Box>
                                      </AccordionSummary>
                                      <AccordionDetails>
                                        <Typography variant="body2" color="grey.300" sx={{ mb: 1 }}>
                                          {vuln.description}
                                        </Typography>
                                        {vuln.affected_code && (
                                          <Box sx={{ 
                                            p: 1, 
                                            bgcolor: alpha(theme.palette.background.paper, 0.3),
                                            borderRadius: 1,
                                            fontFamily: "monospace",
                                            fontSize: "0.75rem",
                                            color: "warning.main",
                                            mb: 1
                                          }}>
                                            {vuln.affected_code}
                                          </Box>
                                        )}
                                        {vuln.impact && (
                                          <Typography variant="caption" color="error.main">
                                            ⚡ Impact: {vuln.impact}
                                          </Typography>
                                        )}
                                      </AccordionDetails>
                                    </Accordion>
                                  ))}
                                </Box>
                              )}

                              {/* Recommendations */}
                              {aiVulnerabilities.recommendations.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" color="success.main" gutterBottom>
                                    💡 Recommendations
                                  </Typography>
                                  <List dense>
                                    {aiVulnerabilities.recommendations.map((rec, idx) => (
                                      <ListItem key={idx} sx={{ py: 0.25 }}>
                                        <ListItemIcon sx={{ minWidth: 24 }}>
                                          <CheckIcon fontSize="small" color="success" />
                                        </ListItemIcon>
                                        <ListItemText 
                                          primary={rec}
                                          primaryTypographyProps={{ variant: "body2", color: "grey.300" }}
                                        />
                                      </ListItem>
                                    ))}
                                  </List>
                                </Box>
                              )}

                              {/* Exploitation Scenarios */}
                              {aiVulnerabilities.exploitation_scenarios.length > 0 && (
                                <Box>
                                  <Typography variant="subtitle2" color="warning.main" gutterBottom>
                                    🎯 Exploitation Scenarios
                                  </Typography>
                                  {aiVulnerabilities.exploitation_scenarios.map((scenario, idx) => (
                                    <Alert 
                                      key={idx}
                                      severity="warning"
                                      sx={{ mb: 1, bgcolor: "transparent", border: 1, borderColor: "warning.dark" }}
                                    >
                                      <Typography variant="body2">{scenario}</Typography>
                                    </Alert>
                                  ))}
                                </Box>
                              )}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4, color: "grey.500" }}>
                              <GppMaybeIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                              <Typography variant="body2">
                                Click the <GppMaybeIcon fontSize="small" sx={{ verticalAlign: "middle" }} /> button to scan for vulnerabilities with AI
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Data Flow Tab */}
                      {aiTab === 3 && (
                        <Box>
                          {dataFlowLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                Analyzing data flow...
                              </Typography>
                            </Box>
                          ) : dataFlow ? (
                            <Box>
                              {/* Summary */}
                              <Box sx={{ 
                                display: "flex", 
                                gap: 2, 
                                mb: 2,
                                p: 1.5,
                                borderRadius: 1,
                                bgcolor: alpha(getSeverityColor(dataFlow.summary.risk_level), 0.15),
                                border: `1px solid ${getSeverityColor(dataFlow.summary.risk_level)}`
                              }}>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="info.main">{dataFlow.summary.total_sources}</Typography>
                                  <Typography variant="caption" color="grey.400">Sources</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="warning.main">{dataFlow.summary.total_sinks}</Typography>
                                  <Typography variant="caption" color="grey.400">Sinks</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="error.main">{dataFlow.summary.potential_leaks}</Typography>
                                  <Typography variant="caption" color="grey.400">Leaks</Typography>
                                </Box>
                                <Chip 
                                  label={dataFlow.summary.risk_level.toUpperCase()} 
                                  sx={{ 
                                    bgcolor: getSeverityColor(dataFlow.summary.risk_level),
                                    color: "white",
                                    fontWeight: 700,
                                    ml: "auto"
                                  }} 
                                />
                              </Box>

                              {/* Risk Flows */}
                              {dataFlow.risk_flows.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" color="error.main" gutterBottom>
                                    🚨 Potential Data Leaks ({dataFlow.risk_flows.length})
                                  </Typography>
                                  {dataFlow.risk_flows.map((flow, idx) => (
                                    <Alert 
                                      key={idx}
                                      severity={flow.risk === "critical" || flow.risk === "high" ? "error" : "warning"}
                                      sx={{ mb: 1, bgcolor: "transparent", border: 1, borderColor: "divider" }}
                                    >
                                      <Box>
                                        <Typography variant="body2" fontWeight={600}>
                                          {flow.source.type} → {flow.sink.type}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          Line {flow.source.line}: {flow.source.variable || "data"} flows to Line {flow.sink.line}
                                        </Typography>
                                        <Box sx={{ 
                                          mt: 0.5, 
                                          p: 0.5, 
                                          bgcolor: alpha(theme.palette.background.paper, 0.3),
                                          borderRadius: 0.5,
                                          fontFamily: "monospace",
                                          fontSize: "0.7rem"
                                        }}>
                                          {flow.sink.code}
                                        </Box>
                                      </Box>
                                    </Alert>
                                  ))}
                                </Box>
                              )}

                              {/* Sources */}
                              {dataFlow.sources.length > 0 && (
                                <Accordion sx={{ bgcolor: alpha(theme.palette.info.main, 0.1), mb: 1 }}>
                                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                    <Typography variant="subtitle2">
                                      📥 Data Sources ({dataFlow.sources.length})
                                    </Typography>
                                  </AccordionSummary>
                                  <AccordionDetails>
                                    <Table size="small">
                                      <TableHead>
                                        <TableRow>
                                          <TableCell sx={{ color: "grey.400" }}>Type</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Line</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Variable</TableCell>
                                        </TableRow>
                                      </TableHead>
                                      <TableBody>
                                        {dataFlow.sources.slice(0, 20).map((src, idx) => (
                                          <TableRow key={idx}>
                                            <TableCell>
                                              <Chip label={src.type} size="small" color="info" />
                                            </TableCell>
                                            <TableCell sx={{ color: "grey.300" }}>{src.line}</TableCell>
                                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace" }}>
                                              {src.variable || "-"}
                                            </TableCell>
                                          </TableRow>
                                        ))}
                                      </TableBody>
                                    </Table>
                                    {dataFlow.sources.length > 20 && (
                                      <Typography variant="caption" color="grey.500" sx={{ mt: 1, display: "block" }}>
                                        + {dataFlow.sources.length - 20} more sources...
                                      </Typography>
                                    )}
                                  </AccordionDetails>
                                </Accordion>
                              )}

                              {/* Sinks */}
                              {dataFlow.sinks.length > 0 && (
                                <Accordion sx={{ bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                    <Typography variant="subtitle2">
                                      📤 Data Sinks ({dataFlow.sinks.length})
                                    </Typography>
                                  </AccordionSummary>
                                  <AccordionDetails>
                                    <Table size="small">
                                      <TableHead>
                                        <TableRow>
                                          <TableCell sx={{ color: "grey.400" }}>Type</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Line</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Code</TableCell>
                                        </TableRow>
                                      </TableHead>
                                      <TableBody>
                                        {dataFlow.sinks.slice(0, 20).map((sink, idx) => (
                                          <TableRow key={idx}>
                                            <TableCell>
                                              <Chip label={sink.type} size="small" color="warning" />
                                            </TableCell>
                                            <TableCell sx={{ color: "grey.300" }}>{sink.line}</TableCell>
                                            <TableCell sx={{ 
                                              color: "grey.300", 
                                              fontFamily: "monospace",
                                              fontSize: "0.7rem",
                                              maxWidth: 200,
                                              overflow: "hidden",
                                              textOverflow: "ellipsis"
                                            }}>
                                              {sink.code}
                                            </TableCell>
                                          </TableRow>
                                        ))}
                                      </TableBody>
                                    </Table>
                                    {dataFlow.sinks.length > 20 && (
                                      <Typography variant="caption" color="grey.500" sx={{ mt: 1, display: "block" }}>
                                        + {dataFlow.sinks.length - 20} more sinks...
                                      </Typography>
                                    )}
                                  </AccordionDetails>
                                </Accordion>
                              )}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4, color: "grey.500" }}>
                              <TimelineIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                              <Typography variant="body2">
                                Click the <TimelineIcon fontSize="small" sx={{ verticalAlign: "middle" }} /> button to analyze data flow
                              </Typography>
                              <Typography variant="caption" color="grey.600" sx={{ display: "block", mt: 1 }}>
                                Track how sensitive data moves through the code
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Call Graph Tab */}
                      {aiTab === 4 && (
                        <Box>
                          {callGraphLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                Building call graph...
                              </Typography>
                            </Box>
                          ) : callGraph ? (
                            <Box>
                              {/* Statistics */}
                              <Box sx={{ 
                                display: "flex", 
                                gap: 2, 
                                mb: 2,
                                p: 1.5,
                                borderRadius: 1,
                                bgcolor: alpha(theme.palette.secondary.main, 0.15),
                                border: `1px solid ${theme.palette.secondary.main}`
                              }}>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="secondary.main">{callGraph.statistics.total_methods}</Typography>
                                  <Typography variant="caption" color="grey.400">Methods</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="primary.main">{callGraph.statistics.total_internal_calls}</Typography>
                                  <Typography variant="caption" color="grey.400">Internal Calls</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="warning.main">{callGraph.statistics.total_external_calls}</Typography>
                                  <Typography variant="caption" color="grey.400">External Calls</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="info.main">{callGraph.statistics.max_depth}</Typography>
                                  <Typography variant="caption" color="grey.400">Max Depth</Typography>
                                </Box>
                                <Box sx={{ textAlign: "center" }}>
                                  <Typography variant="h5" color="error.main">{callGraph.statistics.cyclomatic_complexity}</Typography>
                                  <Typography variant="caption" color="grey.400">Complexity</Typography>
                                </Box>
                              </Box>

                              {/* Entry Points */}
                              {callGraph.entry_points.length > 0 && (
                                <Box sx={{ mb: 2 }}>
                                  <Typography variant="subtitle2" color="success.main" gutterBottom>
                                    🚪 Entry Points ({callGraph.entry_points.length})
                                  </Typography>
                                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                                    {callGraph.entry_points.map((ep, idx) => (
                                      <Chip 
                                        key={idx}
                                        label={`${ep.name} (L${ep.line})`}
                                        size="small"
                                        color="success"
                                        variant="outlined"
                                        sx={{ fontFamily: "monospace" }}
                                      />
                                    ))}
                                  </Box>
                                </Box>
                              )}

                              {/* Methods */}
                              <Accordion sx={{ bgcolor: alpha(theme.palette.secondary.main, 0.1), mb: 1 }}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                  <Typography variant="subtitle2">
                                    📦 Methods ({callGraph.methods.length})
                                  </Typography>
                                </AccordionSummary>
                                <AccordionDetails sx={{ maxHeight: 250, overflow: "auto" }}>
                                  {callGraph.methods.map((method, idx) => (
                                    <Box 
                                      key={idx}
                                      sx={{ 
                                        p: 1, 
                                        mb: 1, 
                                        borderRadius: 1,
                                        bgcolor: alpha(theme.palette.background.paper, 0.3),
                                        border: method.is_entry_point ? `1px solid ${theme.palette.success.main}` : "none"
                                      }}
                                    >
                                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                        <Typography 
                                          variant="body2" 
                                          fontFamily="monospace"
                                          color={method.is_entry_point ? "success.main" : "grey.200"}
                                          fontWeight={600}
                                        >
                                          {method.name}
                                        </Typography>
                                        {method.is_entry_point && (
                                          <Chip label="Entry" size="small" color="success" sx={{ height: 16 }} />
                                        )}
                                        <Typography variant="caption" color="grey.500">
                                          L{method.line_start}-{method.line_end}
                                        </Typography>
                                      </Box>
                                      <Typography variant="caption" color="grey.400" fontFamily="monospace">
                                        {method.return_type} ({method.parameters.length} params) → {method.calls.length} calls
                                      </Typography>
                                    </Box>
                                  ))}
                                </AccordionDetails>
                              </Accordion>

                              {/* Call Relationships */}
                              {callGraph.calls.length > 0 && (
                                <Accordion sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                    <Typography variant="subtitle2">
                                      🔗 Call Relationships ({callGraph.calls.length})
                                    </Typography>
                                  </AccordionSummary>
                                  <AccordionDetails sx={{ maxHeight: 200, overflow: "auto" }}>
                                    <Table size="small">
                                      <TableHead>
                                        <TableRow>
                                          <TableCell sx={{ color: "grey.400" }}>Caller</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>→</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Callee</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Line</TableCell>
                                        </TableRow>
                                      </TableHead>
                                      <TableBody>
                                        {callGraph.calls.slice(0, 30).map((call, idx) => (
                                          <TableRow key={idx}>
                                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace" }}>
                                              {call.caller}
                                            </TableCell>
                                            <TableCell>
                                              <ArrowIcon fontSize="small" color="primary" />
                                            </TableCell>
                                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace" }}>
                                              {call.is_internal ? call.callee : `${call.callee_class}.${call.callee}`}
                                            </TableCell>
                                            <TableCell sx={{ color: "grey.500" }}>{call.line}</TableCell>
                                          </TableRow>
                                        ))}
                                      </TableBody>
                                    </Table>
                                    {callGraph.calls.length > 30 && (
                                      <Typography variant="caption" color="grey.500" sx={{ mt: 1, display: "block" }}>
                                        + {callGraph.calls.length - 30} more calls...
                                      </Typography>
                                    )}
                                  </AccordionDetails>
                                </Accordion>
                              )}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4, color: "grey.500" }}>
                              <AccountTreeIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                              <Typography variant="body2">
                                Click the <AccountTreeIcon fontSize="small" sx={{ verticalAlign: "middle" }} /> button to build call graph
                              </Typography>
                              <Typography variant="caption" color="grey.600" sx={{ display: "block", mt: 1 }}>
                                Visualize method calls and code structure
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* Cross-Reference Tab */}
                      {aiTab === 5 && (
                        <Box>
                          {xrefLoading ? (
                            <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", py: 4 }}>
                              <CircularProgress color="warning" />
                              <Typography variant="body2" color="grey.400" sx={{ mt: 2 }}>
                                Building cross-references...
                              </Typography>
                            </Box>
                          ) : crossRefs ? (
                            <Box>
                              {/* Summary */}
                              <Box sx={{ 
                                p: 1.5,
                                mb: 2,
                                borderRadius: 1,
                                bgcolor: alpha(theme.palette.warning.main, 0.15),
                                border: `1px solid ${theme.palette.warning.main}`
                              }}>
                                <Typography variant="body2" color="grey.300">
                                  {crossRefs.summary}
                                </Typography>
                              </Box>

                              {/* Stats */}
                              <Grid container spacing={1} sx={{ mb: 2 }}>
                                <Grid item xs={3}>
                                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                                    <Typography variant="h5" color="info.main">{crossRefs.statistics.method_count}</Typography>
                                    <Typography variant="caption">Methods</Typography>
                                  </Paper>
                                </Grid>
                                <Grid item xs={3}>
                                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                                    <Typography variant="h5" color="success.main">{crossRefs.statistics.total_incoming_refs}</Typography>
                                    <Typography variant="caption">Incoming</Typography>
                                  </Paper>
                                </Grid>
                                <Grid item xs={3}>
                                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                                    <Typography variant="h5" color="primary.main">{crossRefs.statistics.total_outgoing_refs}</Typography>
                                    <Typography variant="caption">Outgoing</Typography>
                                  </Paper>
                                </Grid>
                                <Grid item xs={3}>
                                  <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.1) }}>
                                    <Typography variant="h5" color="secondary.main">{crossRefs.statistics.field_count}</Typography>
                                    <Typography variant="caption">Fields</Typography>
                                  </Paper>
                                </Grid>
                              </Grid>

                              {/* Methods with References */}
                              <Accordion defaultExpanded sx={{ mb: 1 }}>
                                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                  <Typography variant="subtitle2" color="warning.main">
                                    🔗 Methods ({crossRefs.methods.length})
                                  </Typography>
                                </AccordionSummary>
                                <AccordionDetails sx={{ maxHeight: 300, overflow: "auto" }}>
                                  {crossRefs.methods.map((method, idx) => (
                                    <Accordion 
                                      key={idx} 
                                      sx={{ 
                                        mb: 0.5,
                                        bgcolor: alpha(theme.palette.warning.main, method.caller_count > 5 ? 0.15 : 0.05),
                                        "&:before": { display: "none" }
                                      }}
                                    >
                                      <AccordionSummary expandIcon={<ExpandMoreIcon sx={{ fontSize: 16 }} />}>
                                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                                          <Typography variant="body2" fontFamily="monospace" fontWeight={600} color="grey.200">
                                            {method.name}
                                          </Typography>
                                          <Chip 
                                            label={`↓${method.caller_count}`} 
                                            size="small" 
                                            color="success"
                                            sx={{ height: 18, fontSize: "0.65rem" }}
                                          />
                                          <Chip 
                                            label={`↑${method.callee_count}`} 
                                            size="small" 
                                            color="primary"
                                            sx={{ height: 18, fontSize: "0.65rem" }}
                                          />
                                          <Typography variant="caption" color="grey.500" sx={{ ml: "auto" }}>
                                            L{method.line}
                                          </Typography>
                                        </Box>
                                      </AccordionSummary>
                                      <AccordionDetails>
                                        {method.callers.length > 0 && (
                                          <Box sx={{ mb: 1 }}>
                                            <Typography variant="caption" color="success.main" fontWeight={600}>
                                              Called by ({method.callers.length}):
                                            </Typography>
                                            <List dense sx={{ py: 0 }}>
                                              {method.callers.slice(0, 10).map((caller, cidx) => (
                                                <ListItem key={cidx} sx={{ py: 0.25 }}>
                                                  <ListItemText
                                                    primary={
                                                      <Typography variant="caption" fontFamily="monospace" color="grey.300">
                                                        {caller.class}.{caller.method}() @ L{caller.line}
                                                      </Typography>
                                                    }
                                                  />
                                                </ListItem>
                                              ))}
                                              {method.callers.length > 10 && (
                                                <Typography variant="caption" color="grey.500">
                                                  + {method.callers.length - 10} more...
                                                </Typography>
                                              )}
                                            </List>
                                          </Box>
                                        )}
                                        {method.callees.length > 0 && (
                                          <Box>
                                            <Typography variant="caption" color="primary.main" fontWeight={600}>
                                              Calls ({method.callees.length}):
                                            </Typography>
                                            <List dense sx={{ py: 0 }}>
                                              {method.callees.slice(0, 10).map((callee, cidx) => (
                                                <ListItem key={cidx} sx={{ py: 0.25 }}>
                                                  <ListItemText
                                                    primary={
                                                      <Typography variant="caption" fontFamily="monospace" color="grey.300">
                                                        {callee.object}.{callee.method}() @ L{callee.line}
                                                      </Typography>
                                                    }
                                                  />
                                                </ListItem>
                                              ))}
                                            </List>
                                          </Box>
                                        )}
                                      </AccordionDetails>
                                    </Accordion>
                                  ))}
                                </AccordionDetails>
                              </Accordion>

                              {/* Fields */}
                              {crossRefs.fields.length > 0 && (
                                <Accordion>
                                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                                    <Typography variant="subtitle2" color="secondary.main">
                                      📝 Fields ({crossRefs.fields.length})
                                    </Typography>
                                  </AccordionSummary>
                                  <AccordionDetails>
                                    <Table size="small">
                                      <TableHead>
                                        <TableRow>
                                          <TableCell sx={{ color: "grey.400" }}>Field</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Type</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Reads</TableCell>
                                          <TableCell sx={{ color: "grey.400" }}>Writes</TableCell>
                                        </TableRow>
                                      </TableHead>
                                      <TableBody>
                                        {crossRefs.fields.map((field, idx) => (
                                          <TableRow key={idx}>
                                            <TableCell sx={{ color: "grey.300", fontFamily: "monospace" }}>
                                              {field.name}
                                            </TableCell>
                                            <TableCell sx={{ color: "grey.500", fontFamily: "monospace" }}>
                                              {field.type}
                                            </TableCell>
                                            <TableCell>
                                              <Chip label={field.read_count} size="small" color="info" sx={{ height: 18 }} />
                                            </TableCell>
                                            <TableCell>
                                              <Chip label={field.write_count} size="small" color="warning" sx={{ height: 18 }} />
                                            </TableCell>
                                          </TableRow>
                                        ))}
                                      </TableBody>
                                    </Table>
                                  </AccordionDetails>
                                </Accordion>
                              )}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: "center", py: 4, color: "grey.500" }}>
                              <HubIcon sx={{ fontSize: 48, mb: 2, opacity: 0.5 }} />
                              <Typography variant="body2">
                                Click the <HubIcon fontSize="small" sx={{ verticalAlign: "middle" }} /> button to analyze cross-references
                              </Typography>
                              <Typography variant="caption" color="grey.600" sx={{ display: "block", mt: 1 }}>
                                See who calls this class and what it calls
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}
                    </Box>
                  </Box>
                ) : (
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: 600, color: "grey.500" }}>
                    <Typography>Select a class from the tree to view source code</Typography>
                  </Box>
                )}
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}
    </Paper>
  );
}

// ============================================================================
// Manifest Visualization Component
// ============================================================================

interface ManifestVisualizerProps {
  apkFile: File | null;
  autoStart?: boolean;
}

export function ManifestVisualizer({ apkFile, autoStart = false }: ManifestVisualizerProps) {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ManifestVisualizationResult | null>(null);
  const [selectedNode, setSelectedNode] = useState<ManifestNode | null>(null);
  const [showMermaid, setShowMermaid] = useState(true);
  const [hasAutoStarted, setHasAutoStarted] = useState(false);
  const [useAI, setUseAI] = useState(true);
  const [showAIAnalysis, setShowAIAnalysis] = useState(false);

  const handleVisualize = useCallback(async () => {
    if (!apkFile) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const res = useAI 
        ? await reverseEngineeringClient.getManifestVisualizationAI(apkFile)
        : await reverseEngineeringClient.getManifestVisualization(apkFile);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Visualization failed");
    } finally {
      setLoading(false);
    }
  }, [apkFile, useAI]);

  // Auto-start when prop is set and we have an APK file
  useEffect(() => {
    if (autoStart && apkFile && !hasAutoStarted && !result && !loading) {
      setHasAutoStarted(true);
      handleVisualize();
    }
  }, [autoStart, apkFile, hasAutoStarted, result, loading, handleVisualize]);

  const getNodeIcon = (type: string) => {
    switch (type) {
      case "activity": return "📱";
      case "service": return "⚙️";
      case "receiver": return "📡";
      case "provider": return "🗄️";
      case "permission": return "🔓";
      case "application": return "📦";
      default: return "❓";
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <TreeIcon color="primary" /> Manifest Visualization
        {useAI && <Chip label="AI Enhanced" size="small" color="secondary" />}
      </Typography>
      
      {!result && (
        <Box>
          <Alert severity="info" sx={{ mb: 2 }}>
            Visualize the app's AndroidManifest.xml as an interactive graph:
            <ul style={{ margin: "8px 0" }}>
              <li>See all activities, services, receivers, and providers</li>
              <li>Identify exported components (entry points)</li>
              <li>View dangerous permissions at a glance</li>
              <li>Generate Mermaid diagrams for documentation</li>
              {useAI && <li><strong>AI Analysis:</strong> Component purposes and security assessment</li>}
            </ul>
          </Alert>

          <FormControlLabel
            control={<Switch checked={useAI} onChange={(e) => setUseAI(e.target.checked)} />}
            label="AI-Enhanced Analysis (slower but provides security insights)"
            sx={{ mb: 2 }}
          />
          
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={20} /> : <TreeIcon />}
            onClick={handleVisualize}
            disabled={!apkFile || loading}
            fullWidth
          >
            {loading ? (useAI ? "AI Analyzing Manifest..." : "Analyzing Manifest...") : "Visualize Manifest"}
          </Button>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 2 }}>
          {/* AI Analysis Section */}
          {result.ai_analysis && (
            <Box sx={{ mb: 3 }}>
              <Button
                variant="outlined"
                color="secondary"
                onClick={() => setShowAIAnalysis(!showAIAnalysis)}
                startIcon={<AutoAwesomeIcon />}
                sx={{ mb: 1 }}
              >
                {showAIAnalysis ? "Hide" : "Show"} AI Analysis
              </Button>
              <Collapse in={showAIAnalysis}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.05), border: `1px solid ${theme.palette.secondary.main}` }}>
                  <Typography variant="subtitle2" color="secondary" gutterBottom>
                    🤖 AI App Overview
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {result.ai_analysis}
                  </Typography>
                  
                  {result.security_assessment && (
                    <>
                      <Typography variant="subtitle2" color="error" gutterBottom>
                        🛡️ Security Assessment
                      </Typography>
                      <Typography variant="body2" component="div" sx={{ mb: 2 }}>
                        <pre style={{ whiteSpace: 'pre-wrap', fontFamily: 'inherit', margin: 0 }}>
                          {typeof result.security_assessment === 'string' 
                            ? result.security_assessment 
                            : JSON.stringify(result.security_assessment, null, 2)}
                        </pre>
                      </Typography>
                    </>
                  )}
                  
                  {result.component_purposes && Object.keys(result.component_purposes).length > 0 && (
                    <>
                      <Typography variant="subtitle2" color="primary" gutterBottom>
                        🎯 Component Purposes
                      </Typography>
                      <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                        {Object.entries(result.component_purposes).map(([comp, purpose], idx) => (
                          <Box key={idx} sx={{ mb: 1 }}>
                            <Typography variant="caption" fontWeight={600}>{comp.split('.').pop()}:</Typography>
                            <Typography variant="body2" color="text.secondary">{purpose}</Typography>
                          </Box>
                        ))}
                      </Box>
                    </>
                  )}
                </Paper>
              </Collapse>
            </Box>
          )}

          {/* Header Info */}
          <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Package</Typography>
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
                <Typography variant="body1">{result.version_name || "N/A"}</Typography>
              </Grid>
            </Grid>
          </Paper>

          {/* Stats */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h5" color="primary">{result.component_counts.activities}</Typography>
                <Typography variant="caption">📱 Activities</Typography>
              </Paper>
            </Grid>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h5" color="secondary">{result.component_counts.services}</Typography>
                <Typography variant="caption">⚙️ Services</Typography>
              </Paper>
            </Grid>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h5" color="info.main">{result.component_counts.receivers}</Typography>
                <Typography variant="caption">📡 Receivers</Typography>
              </Paper>
            </Grid>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center" }}>
                <Typography variant="h5" color="warning.main">{result.component_counts.providers}</Typography>
                <Typography variant="caption">🗄️ Providers</Typography>
              </Paper>
            </Grid>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                <Typography variant="h5" color="error">{result.exported_count}</Typography>
                <Typography variant="caption">🔓 Exported</Typography>
              </Paper>
            </Grid>
            <Grid item xs={4} sm={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                <Typography variant="h5" color="error">{result.permission_summary.dangerous}</Typography>
                <Typography variant="caption">⚠️ Dangerous</Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Main Activity */}
          {result.main_activity && (
            <Alert severity="info" sx={{ mb: 2 }}>
              <strong>Main Activity:</strong> {result.main_activity.split('.').pop()}
              <Typography variant="caption" display="block" fontFamily="monospace">
                {result.main_activity}
              </Typography>
            </Alert>
          )}

          {/* Deep Links */}
          {result.deep_link_schemes.length > 0 && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              <strong>Deep Link Schemes:</strong>{" "}
              {result.deep_link_schemes.map((scheme, idx) => (
                <Chip key={idx} label={scheme + "://"} size="small" sx={{ mr: 0.5 }} />
              ))}
            </Alert>
          )}

          {/* Mermaid Diagram Toggle */}
          <Box sx={{ mb: 2, display: "flex", gap: 1 }}>
            <Button
              variant={showMermaid ? "contained" : "outlined"}
              size="small"
              onClick={() => setShowMermaid(true)}
            >
              Diagram View
            </Button>
            <Button
              variant={!showMermaid ? "contained" : "outlined"}
              size="small"
              onClick={() => setShowMermaid(false)}
            >
              Component List
            </Button>
            <Tooltip title="Copy Mermaid code">
              <IconButton 
                size="small"
                onClick={() => copyToClipboard(result.mermaid_diagram)}
              >
                <CopyIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          </Box>

          {showMermaid ? (
            /* Mermaid Diagram - Rendered Inline */
            <MermaidDiagram 
              code={result.mermaid_diagram} 
              title="Manifest Structure Diagram"
              maxHeight={500}
              showControls={true}
              showCodeToggle={true}
            />
          ) : (
            /* Component List */
            <Grid container spacing={2}>
              {/* Activities */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, maxHeight: 400, overflow: "auto" }}>
                  <Typography variant="subtitle2" gutterBottom>
                    📱 Activities ({result.component_counts.activities})
                  </Typography>
                  <List dense>
                    {result.nodes
                      .filter(n => n.node_type === "activity")
                      .map((node, idx) => (
                        <ListItem key={idx} secondaryAction={
                          node.is_exported && (
                            <Chip label="EXPORTED" size="small" color="error" variant="outlined" />
                          )
                        }>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            {node.is_main ? "🚀" : "📱"}
                          </ListItemIcon>
                          <ListItemText
                            primary={node.label}
                            secondary={node.name}
                            primaryTypographyProps={{ fontWeight: node.is_main ? 600 : 400 }}
                            secondaryTypographyProps={{ 
                              fontFamily: "monospace", 
                              fontSize: "0.7rem",
                              sx: { wordBreak: "break-all" }
                            }}
                          />
                        </ListItem>
                      ))}
                  </List>
                </Paper>
              </Grid>

              {/* Services & Receivers */}
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, maxHeight: 400, overflow: "auto" }}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚙️ Services & Receivers
                  </Typography>
                  <List dense>
                    {result.nodes
                      .filter(n => n.node_type === "service" || n.node_type === "receiver")
                      .map((node, idx) => (
                        <ListItem key={idx} secondaryAction={
                          node.is_exported && (
                            <Chip label="EXPORTED" size="small" color="error" variant="outlined" />
                          )
                        }>
                          <ListItemIcon sx={{ minWidth: 32 }}>
                            {getNodeIcon(node.node_type)}
                          </ListItemIcon>
                          <ListItemText
                            primary={node.label}
                            secondary={`${node.node_type} - ${node.name}`}
                            secondaryTypographyProps={{ 
                              fontFamily: "monospace", 
                              fontSize: "0.7rem",
                              sx: { wordBreak: "break-all" }
                            }}
                          />
                        </ListItem>
                      ))}
                  </List>
                </Paper>
              </Grid>

              {/* Dangerous Permissions */}
              <Grid item xs={12}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚠️ Dangerous Permissions ({result.permission_summary.dangerous})
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                    {result.nodes
                      .filter(n => n.node_type === "permission" && n.is_dangerous)
                      .map((node, idx) => (
                        <Chip 
                          key={idx}
                          label={node.label}
                          size="small"
                          color="error"
                          variant="filled"
                        />
                      ))}
                  </Box>
                </Paper>
              </Grid>
            </Grid>
          )}
        </Box>
      )}
    </Paper>
  );
}

// ============================================================================
// Attack Surface Map Component
// ============================================================================

interface AttackSurfaceMapProps {
  apkFile: File | null;
  autoStart?: boolean;
  onResult?: (result: AttackSurfaceMapResult) => void;
}

export function AttackSurfaceMap({ apkFile, autoStart = false, onResult }: AttackSurfaceMapProps) {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AttackSurfaceMapResult | null>(null);
  const [selectedVector, setSelectedVector] = useState<AttackVector | null>(null);
  const [showAttackTree, setShowAttackTree] = useState(true);
  const [hasAutoStarted, setHasAutoStarted] = useState(false);

  const handleAnalyze = useCallback(async () => {
    if (!apkFile) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const res = await reverseEngineeringClient.getAttackSurfaceMap(apkFile);
      setResult(res);
      // Notify parent of the result
      if (onResult) {
        onResult(res);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }, [apkFile, onResult]);

  // Auto-start when prop is set and we have an APK file
  useEffect(() => {
    if (autoStart && apkFile && !hasAutoStarted && !result && !loading) {
      setHasAutoStarted(true);
      handleAnalyze();
    }
  }, [autoStart, apkFile, hasAutoStarted, result, loading, handleAnalyze]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getRiskColor = (level: string) => {
    switch (level.toLowerCase()) {
      case "critical": return theme.palette.error.main;
      case "high": return "#ea580c";
      case "medium": return theme.palette.warning.main;
      case "low": return theme.palette.success.main;
      default: return theme.palette.grey[500];
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <ShieldIcon color="error" /> Attack Surface Map
      </Typography>
      
      {!result && (
        <Box>
          <Alert severity="warning" sx={{ mb: 2 }}>
            Generate a comprehensive attack surface map for penetration testing:
            <ul style={{ margin: "8px 0" }}>
              <li>Identify all exported components (entry points)</li>
              <li>Get ADB commands for testing each vector</li>
              <li>View deep links and URL handlers</li>
              <li>Prioritized attack targets with exploitation steps</li>
            </ul>
          </Alert>
          
          <Button
            variant="contained"
            color="error"
            startIcon={loading ? <CircularProgress size={20} /> : <ShieldIcon />}
            onClick={handleAnalyze}
            disabled={!apkFile || loading}
            fullWidth
          >
            {loading ? "Mapping Attack Surface..." : "Generate Attack Surface Map"}
          </Button>
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 2 }}>
          {/* Risk Summary */}
          <Paper 
            sx={{ 
              p: 3, 
              mb: 3, 
              bgcolor: alpha(getRiskColor(result.risk_level), 0.1),
              border: `2px solid ${getRiskColor(result.risk_level)}`,
            }}
          >
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={4}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="h2" sx={{ color: getRiskColor(result.risk_level) }}>
                    {result.overall_exposure_score}
                  </Typography>
                  <Typography variant="subtitle1" sx={{ textTransform: "uppercase", fontWeight: 600 }}>
                    Exposure Score
                  </Typography>
                  <Chip 
                    label={result.risk_level.toUpperCase()} 
                    sx={{ 
                      bgcolor: getRiskColor(result.risk_level),
                      color: "white",
                      fontWeight: 600,
                    }}
                  />
                </Box>
              </Grid>
              <Grid item xs={12} sm={8}>
                <Typography variant="subtitle2" gutterBottom>Risk Breakdown</Typography>
                <Grid container spacing={1}>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.2) }}>
                      <Typography variant="h5" color="error">{result.risk_breakdown.critical}</Typography>
                      <Typography variant="caption">Critical</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha("#ea580c", 0.2) }}>
                      <Typography variant="h5" sx={{ color: "#ea580c" }}>{result.risk_breakdown.high}</Typography>
                      <Typography variant="caption">High</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.2) }}>
                      <Typography variant="h5" color="warning.main">{result.risk_breakdown.medium}</Typography>
                      <Typography variant="caption">Medium</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.2) }}>
                      <Typography variant="h5" color="success.main">{result.risk_breakdown.low}</Typography>
                      <Typography variant="caption">Low</Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Grid>
            </Grid>
          </Paper>

          {/* Priority Targets */}
          {result.priority_targets.length > 0 && (
            <Alert 
              severity="error" 
              sx={{ mb: 2 }}
              icon={<BugIcon />}
            >
              <Typography variant="subtitle2" gutterBottom>🎯 Priority Targets</Typography>
              <List dense disablePadding>
                {result.priority_targets.map((target, idx) => (
                  <ListItem key={idx} disablePadding>
                    <ListItemText 
                      primary={target}
                      primaryTypographyProps={{ variant: "body2" }}
                    />
                  </ListItem>
                ))}
              </List>
            </Alert>
          )}

          {/* View Toggle */}
          <Box sx={{ mb: 2, display: "flex", gap: 1 }}>
            <Button
              variant={showAttackTree ? "contained" : "outlined"}
              size="small"
              onClick={() => setShowAttackTree(true)}
            >
              Attack Tree
            </Button>
            <Button
              variant={!showAttackTree ? "contained" : "outlined"}
              size="small"
              onClick={() => setShowAttackTree(false)}
            >
              Attack Vectors
            </Button>
          </Box>

          {showAttackTree ? (
            /* Attack Tree Mermaid - Rendered Inline */
            <Box sx={{ mb: 3 }}>
              <MermaidDiagram 
                code={result.mermaid_attack_tree} 
                title="Attack Surface Tree"
                maxHeight={500}
                showControls={true}
                showCodeToggle={true}
              />
            </Box>
          ) : (
            /* Attack Vectors List */
            <Box sx={{ mb: 3 }}>
              {result.attack_vectors.map((vector, idx) => (
                <Accordion key={idx}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                      <Chip
                        label={vector.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(vector.severity), 0.2),
                          color: getSeverityColor(vector.severity),
                          fontWeight: 600,
                          minWidth: 70,
                        }}
                      />
                      <Typography variant="body2" fontWeight={500}>
                        {vector.name}
                      </Typography>
                      <Chip 
                        label={vector.vector_type.replace(/_/g, " ")} 
                        size="small" 
                        variant="outlined"
                        sx={{ ml: "auto" }}
                      />
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" color="text.secondary" gutterBottom>
                      {vector.description}
                    </Typography>
                    
                    <Typography variant="subtitle2" sx={{ mt: 2 }}>
                      🎯 Exploitation Steps:
                    </Typography>
                    <List dense>
                      {vector.exploitation_steps.map((step, stepIdx) => (
                        <ListItem key={stepIdx}>
                          <ListItemIcon sx={{ minWidth: 28 }}>
                            <Typography variant="body2" color="primary">{stepIdx + 1}.</Typography>
                          </ListItemIcon>
                          <ListItemText primary={step} primaryTypographyProps={{ variant: "body2" }} />
                        </ListItem>
                      ))}
                    </List>

                    {vector.adb_command && (
                      <Paper sx={{ p: 1.5, bgcolor: "#1a1a2e", mt: 2 }}>
                        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <Typography variant="caption" color="grey.500">
                            <TerminalIcon fontSize="inherit" /> ADB Command
                          </Typography>
                          <IconButton 
                            size="small"
                            onClick={() => copyToClipboard(vector.adb_command!)}
                            sx={{ color: "grey.400" }}
                          >
                            <CopyIcon fontSize="small" />
                          </IconButton>
                        </Box>
                        <Typography 
                          variant="body2" 
                          fontFamily="monospace"
                          sx={{ color: "#98c379", wordBreak: "break-all" }}
                        >
                          {vector.adb_command}
                        </Typography>
                      </Paper>
                    )}

                    {vector.mitigation && (
                      <Alert severity="info" sx={{ mt: 2 }}>
                        <Typography variant="caption" fontWeight={600}>Mitigation:</Typography>
                        <Typography variant="body2">{vector.mitigation}</Typography>
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Box>
          )}

          {/* Deep Links */}
          {result.deep_links.length > 0 && (
            <Paper sx={{ p: 2, mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <LinkIcon /> Deep Links ({result.deep_links.length})
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>URL</TableCell>
                      <TableCell>Handler</TableCell>
                      <TableCell>Verified</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.deep_links.map((link, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                            {link.full_url}
                          </Typography>
                          {link.security_notes.map((note, nIdx) => (
                            <Typography key={nIdx} variant="caption" color="warning.main" display="block">
                              {note}
                            </Typography>
                          ))}
                        </TableCell>
                        <TableCell>
                          <Typography variant="caption" fontFamily="monospace">
                            {link.handling_activity.split('.').pop()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip 
                            label={link.is_verified ? "Verified" : "Not Verified"}
                            size="small"
                            color={link.is_verified ? "success" : "warning"}
                            variant="outlined"
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title="Copy deep link test command">
                            <IconButton 
                              size="small"
                              onClick={() => copyToClipboard(`adb shell am start -W -a android.intent.action.VIEW -d "${link.full_url}"`)}
                            >
                              <CopyIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          )}

          {/* Automated Tests */}
          <Accordion>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <PlayIcon color="primary" /> Automated Test Commands ({result.automated_tests.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="caption" color="text.secondary" gutterBottom display="block">
                Run these ADB commands to test each attack vector. Make sure you have ADB installed and the device connected.
              </Typography>
              <List dense>
                {result.automated_tests.map((test, idx) => (
                  <ListItem 
                    key={idx}
                    secondaryAction={
                      <IconButton 
                        edge="end"
                        onClick={() => copyToClipboard(test.command)}
                      >
                        <CopyIcon fontSize="small" />
                      </IconButton>
                    }
                  >
                    <ListItemIcon>
                      <TerminalIcon fontSize="small" color="primary" />
                    </ListItemIcon>
                    <ListItemText
                      primary={test.name}
                      secondary={
                        <Typography 
                          variant="caption" 
                          component="pre"
                          sx={{ 
                            fontFamily: "monospace", 
                            bgcolor: alpha(theme.palette.primary.main, 0.1),
                            p: 0.5,
                            borderRadius: 1,
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                          }}
                        >
                          {test.command}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </AccordionDetails>
          </Accordion>
        </Box>
      )}
    </Paper>
  );
}

// ============================================================================
// Obfuscation Analyzer Component
// ============================================================================

interface ObfuscationAnalyzerProps {
  apkFile: File | null;
  autoStart?: boolean;
}

// Obfuscation level colors
const getObfuscationLevelColor = (level: string): string => {
  switch (level.toLowerCase()) {
    case "extreme":
      return "#7c3aed";
    case "heavy":
      return "#dc2626";
    case "moderate":
      return "#ea580c";
    case "light":
      return "#ca8a04";
    case "none":
      return "#16a34a";
    default:
      return "#6b7280";
  }
};

export function ObfuscationAnalyzer({ apkFile, autoStart = false }: ObfuscationAnalyzerProps) {
  const theme = useTheme();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ObfuscationAnalysisResult | null>(null);
  const [selectedTab, setSelectedTab] = useState(0);
  const [hasAutoStarted, setHasAutoStarted] = useState(false);
  const [useAI, setUseAI] = useState(true);
  const [showAISummary, setShowAISummary] = useState(false);

  const handleAnalyze = useCallback(async () => {
    if (!apkFile) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const res = useAI
        ? await reverseEngineeringClient.analyzeObfuscationAI(apkFile)
        : await reverseEngineeringClient.analyzeObfuscation(apkFile);
      setResult(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
    } finally {
      setLoading(false);
    }
  }, [apkFile, useAI]);

  // Auto-start when prop is set and we have an APK file
  useEffect(() => {
    if (autoStart && apkFile && !hasAutoStarted && !result && !loading) {
      setHasAutoStarted(true);
      handleAnalyze();
    }
  }, [autoStart, apkFile, hasAutoStarted, result, loading, handleAnalyze]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case "high": return theme.palette.error.main;
      case "medium": return theme.palette.warning.main;
      case "low": return theme.palette.info.main;
      default: return theme.palette.grey[500];
    }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <LayersIcon color="secondary" /> Obfuscation Analysis
        {useAI && <Chip label="AI Enhanced" size="small" color="secondary" />}
      </Typography>
      
      {!result && (
        <Box>
          <Alert severity="info" sx={{ mb: 2 }}>
            Analyze the APK for obfuscation techniques and protection mechanisms:
            <ul style={{ margin: "8px 0" }}>
              <li>Detect ProGuard, DexGuard, and other obfuscators</li>
              <li>Identify string encryption patterns</li>
              <li>Analyze control flow obfuscation</li>
              <li>Get deobfuscation strategies and Frida hooks</li>
              {useAI && <li><strong>AI Analysis:</strong> Tool identification and custom deobfuscation strategies</li>}
            </ul>
          </Alert>

          <FormControlLabel
            control={<Switch checked={useAI} onChange={(e) => setUseAI(e.target.checked)} />}
            label="AI-Enhanced Analysis (slower but provides smarter strategies)"
            sx={{ mb: 2 }}
          />
          
          <Button
            variant="contained"
            color="secondary"
            startIcon={loading ? <CircularProgress size={20} /> : <LayersIcon />}
            onClick={handleAnalyze}
            disabled={!apkFile || loading}
            fullWidth
          >
            {loading ? (useAI ? "AI Analyzing Obfuscation..." : "Analyzing Obfuscation...") : "Analyze Obfuscation"}
          </Button>
          
          {loading && (
            <Box sx={{ mt: 2 }}>
              <LinearProgress color="secondary" />
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                {useAI ? "AI analyzing bytecode patterns and code samples..." : "Scanning bytecode patterns and class structures..."}
              </Typography>
            </Box>
          )}
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {result && (
        <Box sx={{ mt: 2 }}>
          {/* AI Analysis Summary */}
          {result.ai_analysis_summary && (
            <Box sx={{ mb: 3 }}>
              <Button
                variant="outlined"
                color="secondary"
                onClick={() => setShowAISummary(!showAISummary)}
                startIcon={<AutoAwesomeIcon />}
                sx={{ mb: 1 }}
              >
                {showAISummary ? "Hide" : "Show"} AI Analysis
              </Button>
              <Collapse in={showAISummary}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.05), border: `1px solid ${theme.palette.secondary.main}` }}>
                  <Typography variant="subtitle2" color="secondary" gutterBottom>
                    🤖 AI Analysis Summary
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 2 }}>
                    {result.ai_analysis_summary}
                  </Typography>
                  
                  {result.reverse_engineering_difficulty && (
                    <>
                      <Typography variant="subtitle2" color="warning.main" gutterBottom>
                        ⚡ Reverse Engineering Difficulty
                      </Typography>
                      <Chip 
                        label={result.reverse_engineering_difficulty.toUpperCase()}
                        color={
                          result.reverse_engineering_difficulty.includes('difficult') ? 'error' :
                          result.reverse_engineering_difficulty.includes('moderate') || result.reverse_engineering_difficulty.includes('challenging') ? 'warning' :
                          'success'
                        }
                        sx={{ mb: 2 }}
                      />
                    </>
                  )}
                  
                  {result.ai_recommended_approach && (
                    <>
                      <Typography variant="subtitle2" color="primary" gutterBottom>
                        🎯 Recommended Approach
                      </Typography>
                      <Typography variant="body2">
                        {result.ai_recommended_approach}
                      </Typography>
                    </>
                  )}
                </Paper>
              </Collapse>
            </Box>
          )}

          {/* Obfuscation Score Header */}
          <Paper 
            sx={{ 
              p: 3, 
              mb: 3, 
              bgcolor: alpha(getObfuscationLevelColor(result.overall_obfuscation_level), 0.1),
              border: `2px solid ${getObfuscationLevelColor(result.overall_obfuscation_level)}`,
            }}
          >
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} sm={4}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography 
                    variant="h2" 
                    sx={{ color: getObfuscationLevelColor(result.overall_obfuscation_level) }}
                  >
                    {result.obfuscation_score}
                  </Typography>
                  <Typography variant="subtitle1" sx={{ textTransform: "uppercase", fontWeight: 600 }}>
                    Obfuscation Score
                  </Typography>
                  <Chip 
                    label={result.overall_obfuscation_level.toUpperCase()} 
                    sx={{ 
                      bgcolor: getObfuscationLevelColor(result.overall_obfuscation_level),
                      color: "white",
                      fontWeight: 600,
                    }}
                  />
                </Box>
              </Grid>
              <Grid item xs={12} sm={8}>
                <Typography variant="subtitle2" gutterBottom>Detected Tools</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                  {result.detected_tools.length > 0 ? (
                    result.detected_tools.map((tool, idx) => (
                      <Chip key={idx} label={tool} size="small" variant="outlined" />
                    ))
                  ) : (
                    <Typography variant="body2" color="text.secondary">No specific tools detected</Typography>
                  )}
                </Box>
                <Typography variant="subtitle2" gutterBottom>Class Naming Analysis</Typography>
                <Grid container spacing={1}>
                  <Grid item xs={6}>
                    <Typography variant="body2">
                      Obfuscated: <strong>{Math.round(result.class_naming.obfuscation_ratio * 100)}%</strong>
                    </Typography>
                  </Grid>
                  <Grid item xs={6}>
                    <Typography variant="body2">
                      Total Classes: <strong>{result.class_naming.total_classes}</strong>
                    </Typography>
                  </Grid>
                </Grid>
                <LinearProgress 
                  variant="determinate" 
                  value={result.class_naming.obfuscation_ratio * 100} 
                  sx={{ mt: 1, height: 8, borderRadius: 1 }}
                  color={result.class_naming.obfuscation_ratio > 0.5 ? "error" : "warning"}
                />
              </Grid>
            </Grid>
          </Paper>

          {/* Warnings */}
          {result.warnings.length > 0 && (
            <Alert severity="warning" sx={{ mb: 2 }}>
              {result.warnings.join("; ")}
            </Alert>
          )}

          {/* Tabs */}
          <Tabs 
            value={selectedTab} 
            onChange={(_, v) => setSelectedTab(v)}
            sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}
          >
            <Tab label={`Indicators (${result.indicators.length})`} />
            <Tab label={`String Encryption (${result.string_encryption.length})`} />
            <Tab label="Frida Hooks" />
            <Tab label="Strategies" />
          </Tabs>

          {/* Indicators Tab */}
          {selectedTab === 0 && (
            <Box>
              {result.indicators.length === 0 ? (
                <Alert severity="success">No significant obfuscation indicators detected</Alert>
              ) : (
                result.indicators.map((indicator, idx) => (
                  <Accordion key={idx} defaultExpanded={idx === 0}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                        <Chip
                          label={indicator.confidence}
                          size="small"
                          sx={{
                            bgcolor: alpha(getConfidenceColor(indicator.confidence), 0.2),
                            color: getConfidenceColor(indicator.confidence),
                            fontWeight: 600,
                            minWidth: 60,
                          }}
                        />
                        <Typography variant="body2" fontWeight={500}>
                          {indicator.indicator_type.replace(/_/g, " ").toUpperCase()}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Typography variant="body2" gutterBottom>
                        {indicator.description}
                      </Typography>
                      
                      {indicator.evidence.length > 0 && (
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="caption" color="text.secondary">Evidence:</Typography>
                          <Paper sx={{ p: 1, bgcolor: alpha(theme.palette.background.default, 0.5), mt: 0.5 }}>
                            <List dense disablePadding>
                              {indicator.evidence.slice(0, 5).map((ev, evIdx) => (
                                <ListItem key={evIdx} disablePadding>
                                  <ListItemText 
                                    primary={ev}
                                    primaryTypographyProps={{ 
                                      variant: "caption", 
                                      fontFamily: "monospace",
                                      sx: { wordBreak: "break-all" }
                                    }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Paper>
                        </Box>
                      )}

                      {indicator.deobfuscation_hint && (
                        <Alert severity="info" sx={{ mt: 1 }} icon={<BugIcon fontSize="small" />}>
                          <Typography variant="caption">
                            <strong>Tip:</strong> {indicator.deobfuscation_hint}
                          </Typography>
                        </Alert>
                      )}
                    </AccordionDetails>
                  </Accordion>
                ))
              )}

              {/* Control Flow */}
              {result.control_flow.length > 0 && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>Control Flow Obfuscation</Typography>
                  <TableContainer component={Paper} variant="outlined">
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Pattern</TableCell>
                          <TableCell>Affected Methods</TableCell>
                          <TableCell>Complexity</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.control_flow.map((cf, idx) => (
                          <TableRow key={idx}>
                            <TableCell>{cf.pattern_type.replace(/_/g, " ")}</TableCell>
                            <TableCell>{cf.affected_methods}</TableCell>
                            <TableCell>
                              <LinearProgress 
                                variant="determinate" 
                                value={cf.complexity_score * 100}
                                sx={{ width: 80 }}
                              />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              {/* Native Protection */}
              {result.native_protection.has_native_libs && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>Native Libraries</Typography>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                    <Typography variant="body2" gutterBottom>
                      <strong>{result.native_protection.native_lib_names.length}</strong> native libraries found
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {result.native_protection.native_lib_names.slice(0, 10).map((lib, idx) => (
                        <Chip 
                          key={idx} 
                          label={lib.split('/').pop()} 
                          size="small" 
                          variant="outlined"
                        />
                      ))}
                    </Box>
                    {result.native_protection.protection_indicators.length > 0 && (
                      <Alert severity="warning" sx={{ mt: 1 }}>
                        Protection detected: {result.native_protection.protection_indicators.join(", ")}
                      </Alert>
                    )}
                  </Paper>
                </Box>
              )}
            </Box>
          )}

          {/* String Encryption Tab */}
          {selectedTab === 1 && (
            <Box>
              {result.string_encryption.length === 0 ? (
                <Alert severity="info">No string encryption patterns detected</Alert>
              ) : (
                result.string_encryption.map((pattern, idx) => (
                  <Accordion key={idx}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <Chip label={pattern.pattern_name} size="small" color="secondary" />
                        <Typography variant="body2">
                          {pattern.class_name.split('/').pop()?.replace(';', '')}
                        </Typography>
                      </Box>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Class</Typography>
                          <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                            {pattern.class_name}
                          </Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Method</Typography>
                          <Typography variant="body2" fontFamily="monospace">
                            {pattern.method_name}
                          </Typography>
                        </Grid>
                      </Grid>

                      {pattern.suggested_frida_hook && (
                        <Box sx={{ mt: 2 }}>
                          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <Typography variant="caption" color="text.secondary">
                              Suggested Frida Hook
                            </Typography>
                            <IconButton 
                              size="small"
                              onClick={() => copyToClipboard(pattern.suggested_frida_hook!)}
                            >
                              <CopyIcon fontSize="small" />
                            </IconButton>
                          </Box>
                          <Paper sx={{ p: 1.5, bgcolor: "#1a1a2e", mt: 0.5 }}>
                            <Typography 
                              variant="body2" 
                              component="pre"
                              sx={{ 
                                m: 0,
                                fontFamily: "monospace",
                                fontSize: "0.75rem",
                                color: "#98c379",
                                whiteSpace: "pre-wrap",
                                wordBreak: "break-all",
                              }}
                            >
                              {pattern.suggested_frida_hook}
                            </Typography>
                          </Paper>
                        </Box>
                      )}
                    </AccordionDetails>
                  </Accordion>
                ))
              )}
            </Box>
          )}

          {/* Frida Hooks Tab */}
          {selectedTab === 2 && (
            <Box>
              <Alert severity="info" sx={{ mb: 2 }}>
                Use these Frida scripts to dynamically analyze the APK at runtime.
                Run with: <code>frida -U -f {result.package_name} -l script.js</code>
              </Alert>
              
              {result.frida_hooks.map((hook, idx) => (
                <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: "#1a1a2e" }}>
                  <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                    <Typography variant="caption" color="grey.500">
                      Hook #{idx + 1}
                    </Typography>
                    <IconButton 
                      size="small"
                      onClick={() => copyToClipboard(hook)}
                      sx={{ color: "grey.400" }}
                    >
                      <CopyIcon fontSize="small" />
                    </IconButton>
                  </Box>
                  <Typography 
                    variant="body2" 
                    component="pre"
                    sx={{ 
                      m: 0,
                      fontFamily: "monospace",
                      fontSize: "0.75rem",
                      color: "#abb2bf",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                      maxHeight: 200,
                      overflow: "auto",
                    }}
                  >
                    {hook}
                  </Typography>
                </Paper>
              ))}
            </Box>
          )}

          {/* Strategies Tab */}
          {selectedTab === 3 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>Deobfuscation Strategies</Typography>
              <List>
                {result.deobfuscation_strategies.map((strategy, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon>
                      <CheckIcon color="success" fontSize="small" />
                    </ListItemIcon>
                    <ListItemText primary={strategy} />
                  </ListItem>
                ))}
              </List>

              <Divider sx={{ my: 2 }} />

              <Typography variant="subtitle2" gutterBottom>Recommended Tools</Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {result.recommended_tools.map((tool, idx) => (
                  <Chip 
                    key={idx} 
                    label={tool.split(' - ')[0]} 
                    variant="outlined"
                    title={tool}
                  />
                ))}
              </Box>

              <Alert severity="info" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  <strong>Analysis Time:</strong> {result.analysis_time.toFixed(2)}s
                </Typography>
              </Alert>
            </Box>
          )}
        </Box>
      )}
    </Paper>
  );
}
