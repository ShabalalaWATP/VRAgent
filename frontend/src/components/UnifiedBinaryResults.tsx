/**
 * UnifiedBinaryResults - Comprehensive Binary Analysis Results Display
 * 
 * Displays binary analysis results in a tabbed interface matching the APK scanner:
 * - Tab 1: What Does This Binary Do? (AI functionality report)
 * - Tab 2: Security Findings (formatted vulnerabilities with explanations)
 * - Tab 3: Architecture Diagram (Mermaid)
 * - Tab 4: Attack Surface Map (Mermaid)
 */

import React, { useState, useMemo, useCallback, Component, ReactNode } from "react";
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Grid,
  Chip,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Tooltip,
  Divider,
  alpha,
  useTheme,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import {
  Info as InfoIcon,
  Security as SecurityIcon,
  AccountTree as ArchitectureIcon,
  Shield as ShieldIcon,
  ExpandMore as ExpandMoreIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
  Error as ErrorIcon,
  BugReport as BugIcon,
  Memory as BinaryIcon,
  VpnKey as SecretIcon,
  Functions as FunctionIcon,
  Code as CodeIcon,
  Timeline as SymbolicIcon,
  TrendingUp as PathIcon,
} from "@mui/icons-material";
import { MermaidDiagram } from "./MermaidDiagram";
import { formatMarkdownSafe } from "../utils/sanitizeHtml";
import type { BinaryAnalysisResult } from "../api/client";

// Error Boundary to catch rendering crashes
interface ErrorBoundaryProps {
  children: ReactNode;
  fallback: ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
}

class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback;
    }
    return this.props.children;
  }
}

// Severity colors
const getSeverityColor = (severity: string): string => {
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

type AnyRecord = Record<string, unknown>;

const normalizeReportText = (value: unknown): string | undefined => {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (["not available", "n/a", "none", "null", "undefined"].includes(trimmed.toLowerCase())) {
    return undefined;
  }
  return trimmed;
};

const collectNestedRecords = (root: unknown, maxDepth = 5): AnyRecord[] => {
  const records: AnyRecord[] = [];
  const seen = new Set<unknown>();
  const walk = (node: unknown, depth: number): void => {
    if (depth > maxDepth || node == null) return;
    if (Array.isArray(node)) {
      node.forEach((item) => walk(item, depth + 1));
      return;
    }
    if (typeof node !== "object") return;
    if (seen.has(node)) return;
    seen.add(node);
    const record = node as AnyRecord;
    records.push(record);
    Object.values(record).forEach((value) => walk(value, depth + 1));
  };
  walk(root, 0);
  return records;
};

const pickText = (records: AnyRecord[], keys: string[]): string | undefined => {
  for (const record of records) {
    for (const key of keys) {
      const cleaned = normalizeReportText(record[key]);
      if (cleaned) return cleaned;
    }
  }
  return undefined;
};

interface UnifiedBinaryResultsProps {
  result: BinaryAnalysisResult;
  reportTitle?: string;
  onSaveReport?: () => void;
}

export function UnifiedBinaryResults({ result, reportTitle, onSaveReport }: UnifiedBinaryResultsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const normalizedReportTitle = (reportTitle || "").trim();
  const headerTitle = normalizedReportTitle || result.filename;

  const fallbackRecords = useMemo(() => collectNestedRecords(result as unknown, 6), [result]);

  const functionalityReport = useMemo(() => (
    normalizeReportText(result.ai_functionality_report) ||
    pickText(fallbackRecords, [
      "ai_functionality_report",
      "ai_report_functionality",
      "functionality_report",
      "functionality",
      "report_functionality",
      "binary_functionality_report",
      "what_does_binary_do",
    ]) ||
    normalizeReportText(result.ai_analysis)
  ), [result.ai_functionality_report, result.ai_analysis, fallbackRecords]);

  const securityReport = useMemo(() => (
    normalizeReportText(result.ai_security_report) ||
    pickText(fallbackRecords, [
      "ai_security_report",
      "ai_report_security",
      "security_report",
      "security",
      "report_security",
      "binary_security_report",
    ]) ||
    normalizeReportText(result.ai_analysis)
  ), [result.ai_security_report, result.ai_analysis, fallbackRecords]);
  
  // Memoize extracted analysis results to prevent recalculation
  const analysisData = useMemo(() => {
    const patternFindings = result.pattern_scan_result?.findings || [];
    const cveFindings = result.cve_lookup_result?.findings || [];
    const verificationResult = result.verification_result;
    const obfuscation = result.obfuscation_analysis;
    const attackSurface = result.attack_surface;
    
    const allFindings = [
      ...patternFindings.map(f => ({ ...f, source: 'pattern' })),
      ...cveFindings.map(f => ({ ...f, source: 'cve' })),
    ];
    
    // Use verified findings if available, otherwise use raw findings
    const displayFindings = verificationResult?.verified_vulnerabilities?.length
      ? verificationResult.verified_vulnerabilities
      : allFindings;
    
    // Calculate severity counts
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    displayFindings.forEach(f => {
      const sev = (f.severity || 'info').toLowerCase();
      if (sev in severityCounts) {
        severityCounts[sev as keyof typeof severityCounts]++;
      }
    });
    
    const calculatedRisk = 
      severityCounts.critical > 0 ? 'critical' : 
      severityCounts.high > 0 ? 'high' : 
      severityCounts.medium > 0 ? 'medium' : 'low';
    
    const overallRisk = verificationResult?.overall_risk || 
      (result.is_legitimate_software && displayFindings.length === 0 ? 'low' : calculatedRisk);
    
    return {
      patternFindings,
      cveFindings,
      verificationResult,
      obfuscation,
      attackSurface,
      allFindings,
      displayFindings,
      severityCounts,
      overallRisk,
    };
  }, [result]);
  
  const { 
    verificationResult, 
    obfuscation, 
    attackSurface, 
    displayFindings, 
    severityCounts, 
    overallRisk 
  } = analysisData;
  
  // Memoize HTML content styles
  const htmlContentStyles = useMemo(() => ({
    fontFamily: theme.typography.fontFamily,
    "& h1, & h2": {
      fontSize: "1.3rem",
      fontWeight: 700,
      color: theme.palette.text.primary,
      mt: 3,
      mb: 1.5,
      pt: 1,
      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
      pb: 1,
    },
    "& h1:first-of-type, & h2:first-of-type": { mt: 0, pt: 0 },
    "& h3": {
      fontSize: "1.15rem",
      fontWeight: 700,
      color: theme.palette.text.primary,
      mt: 2.5,
      mb: 1,
    },
    "& h4": {
      fontSize: "1rem",
      fontWeight: 600,
      mt: 2,
      mb: 1,
    },
    "& p": {
      mb: 1.5,
      lineHeight: 1.8,
      color: theme.palette.text.secondary,
    },
    "& ul, & ol": { pl: 3, mb: 2 },
    "& li": { mb: 1, lineHeight: 1.7, color: theme.palette.text.secondary },
    "& code": {
      bgcolor: alpha(theme.palette.grey[500], 0.15),
      px: 0.75,
      py: 0.25,
      borderRadius: 0.5,
      fontFamily: "monospace",
      fontSize: "0.85em",
    },
    "& pre": {
      bgcolor: alpha(theme.palette.grey[900], 0.8),
      p: 2,
      borderRadius: 1,
      overflow: "auto",
      "& code": { bgcolor: "transparent", p: 0 },
    },
    "& table": {
      width: "100%",
      borderCollapse: "collapse",
      mb: 2,
    },
    "& th, & td": {
      border: `1px solid ${theme.palette.divider}`,
      p: 1,
      textAlign: "left",
    },
    "& th": {
      bgcolor: alpha(theme.palette.primary.main, 0.1),
      fontWeight: 600,
    },
    "& strong": {
      color: theme.palette.text.primary,
    },
  }), [theme]);
  
  // Convert markdown-style content to displayable format - memoized
  // Uses safe sanitization to prevent XSS attacks
  const formatMarkdownContent = useCallback((content: string): string => {
    if (!content) return '';

    // Use sanitized markdown conversion to prevent XSS
    let html = formatMarkdownSafe(content);

    // Wrap in paragraphs if needed
    if (html && !html.startsWith('<')) {
      html = '<p>' + html + '</p>';
    }

    return html;
  }, []);

  // Memoize tab change handler
  const handleTabChange = useCallback((_event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  }, []);

  return (
    <Box>
      {/* Summary Header */}
      <Paper sx={{ 
        p: 3, 
        mb: 3, 
        background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)` 
      }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <Typography variant="h5" fontWeight="bold" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BinaryIcon color="primary" /> {headerTitle}
            </Typography>
            {normalizedReportTitle && normalizedReportTitle !== result.filename && (
              <Typography variant="body2" color="text.secondary">
                File: {result.filename}
              </Typography>
            )}
            <Typography variant="body2" color="text.secondary">
              {result.metadata.file_type} • {result.metadata.architecture} • {(result.metadata.file_size / 1024).toFixed(1)} KB
              {result.metadata.compile_time && ` • Compiled: ${result.metadata.compile_time}`}
            </Typography>
            {result.is_legitimate_software && (
              <Chip 
                icon={<CheckIcon />}
                label="Legitimate Software Detected"
                color="success"
                size="small"
                sx={{ mt: 1 }}
              />
            )}
          </Grid>
          <Grid item xs={12} md={6}>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", justifyContent: { xs: "flex-start", md: "flex-end" } }}>
              <Chip 
                icon={<BugIcon />} 
                label={`${displayFindings.length} Findings`}
                color={displayFindings.length > 10 ? "error" : displayFindings.length > 0 ? "warning" : "success"}
                size="small"
              />
              <Chip 
                icon={<SecretIcon />} 
                label={`${(result.secrets || []).length} Secrets`}
                color={(result.secrets || []).length > 0 ? "warning" : "success"}
                size="small"
              />
              <Chip 
                icon={<FunctionIcon />} 
                label={`${(result.imports || []).length} Imports`}
                color="info"
                size="small"
              />
              <Chip 
                icon={<CodeIcon />} 
                label={`${result.strings_count || 0} Strings`}
                variant="outlined"
                size="small"
              />
            </Box>
          </Grid>
        </Grid>
        
        {/* Legitimacy Indicators */}
        {result.legitimacy_indicators && result.legitimacy_indicators.length > 0 && (
          <Box sx={{ mt: 2, display: "flex", gap: 0.5, flexWrap: "wrap" }}>
            <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
              Legitimacy indicators:
            </Typography>
            {result.legitimacy_indicators.slice(0, 3).map((indicator, idx) => (
              <Chip key={idx} label={indicator} size="small" variant="outlined" color="success" sx={{ height: 20, fontSize: "0.7rem" }} />
            ))}
          </Box>
        )}
      </Paper>
      
      {/* Risk Summary Bar - Different display for legitimate software */}
      {result.is_legitimate_software ? (
        <Paper sx={{ 
          p: 2, 
          mb: 3, 
          bgcolor: alpha(theme.palette.success.main, 0.1),
          border: `1px solid ${theme.palette.success.main}`
        }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Chip 
              icon={<CheckIcon />}
              label="TRUSTED SOFTWARE" 
              sx={{ 
                bgcolor: theme.palette.success.main,
                color: "white",
                fontWeight: 700
              }} 
            />
            <Typography variant="body2">
              This binary is from a known publisher. Automated vulnerability scans may show false positives for legitimate software features.
            </Typography>
          </Box>
          
          {/* Show security posture instead of vulnerability counts */}
          <Grid container spacing={1}>
            <Grid item xs={3}>
              <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.15) }}>
                <Typography variant="h5" sx={{ color: theme.palette.success.main, fontWeight: 700 }}>
                  ✓
                </Typography>
                <Typography variant="caption">Signed</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.15) }}>
                <Typography variant="h5" sx={{ color: theme.palette.success.main, fontWeight: 700 }}>
                  {result.metadata.mitigations?.aslr ? '✓' : '—'}
                </Typography>
                <Typography variant="caption">ASLR</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.15) }}>
                <Typography variant="h5" sx={{ color: theme.palette.success.main, fontWeight: 700 }}>
                  {result.metadata.mitigations?.dep ? '✓' : '—'}
                </Typography>
                <Typography variant="caption">DEP</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.15) }}>
                <Typography variant="h5" sx={{ color: theme.palette.success.main, fontWeight: 700 }}>
                  {result.metadata.mitigations?.cfg ? '✓' : '—'}
                </Typography>
                <Typography variant="caption">CFG</Typography>
              </Paper>
            </Grid>
          </Grid>
        </Paper>
      ) : (
        <Paper sx={{ 
          p: 2, 
          mb: 3, 
          bgcolor: alpha(getSeverityColor(overallRisk), 0.1),
          border: `1px solid ${getSeverityColor(overallRisk)}`
        }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
            <Chip 
              label={`${overallRisk.toUpperCase()} RISK`} 
              sx={{ 
                bgcolor: getSeverityColor(overallRisk),
                color: "white",
                fontWeight: 700
              }} 
            />
            <Typography variant="body2">
              {verificationResult?.summary 
                ? `${verificationResult.summary.verified_total} verified findings, ${verificationResult.summary.filtered_total} filtered as false positives`
                : `${displayFindings.length} total findings from automated analysis`}
            </Typography>
          </Box>
          
          {/* Severity Breakdown */}
          <Grid container spacing={1}>
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(severity => (
              <Grid item xs={2.4} key={severity}>
                <Paper sx={{ p: 1, textAlign: "center", bgcolor: alpha(getSeverityColor(severity), 0.15) }}>
                  <Typography variant="h5" sx={{ color: getSeverityColor(severity), fontWeight: 700 }}>
                    {severityCounts[severity]}
                  </Typography>
                  <Typography variant="caption" sx={{ textTransform: "capitalize" }}>
                    {severity}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Paper>
      )}
      
      {/* Main Tabs */}
      <Paper sx={{ overflow: "hidden" }}>
        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          variant="scrollable"
          scrollButtons="auto"
          sx={{ borderBottom: 1, borderColor: "divider" }}
        >
          <Tab icon={<InfoIcon />} label="What Does This Binary Do?" iconPosition="start" />
          <Tab icon={<SecurityIcon />} label="Security Findings" iconPosition="start" />
          <Tab icon={<ArchitectureIcon />} label="Architecture Diagram" iconPosition="start" />
          <Tab icon={<ShieldIcon />} label="Attack Surface Map" iconPosition="start" />
          <Tab icon={<BinaryIcon />} label="Entropy Analysis" iconPosition="start" />
          <Tab icon={<SymbolicIcon />} label="Symbolic Execution" iconPosition="start" />
        </Tabs>
        
        <Box sx={{ p: 3 }}>
          {/* Tab 0: What Does This Binary Do? */}
          {activeTab === 0 && (
            functionalityReport ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  This report explains the binary's purpose, capabilities, and behavior based on AI analysis of its code, imports, and strings.
                </Alert>
                <Box 
                  sx={htmlContentStyles} 
                  dangerouslySetInnerHTML={{ __html: formatMarkdownContent(functionalityReport) }} 
                />
              </Box>
            ) : (
              <Box>
                <Alert severity="warning" sx={{ mb: 2 }}>
                  AI functionality report not available. Here's what we can determine from static analysis:
                </Alert>
                
                {/* Auto-generated summary based on available data */}
                <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                  <Typography variant="h6" gutterBottom>Binary Overview</Typography>
                  <Typography paragraph>
                    This is a <strong>{result.metadata.file_type}</strong> binary compiled for <strong>{result.metadata.architecture}</strong> architecture.
                    {result.metadata.is_packed && ` The binary appears to be packed with ${result.metadata.packer_name || 'an unknown packer'}.`}
                  </Typography>
                  
                  {result.metadata.version_info && Object.keys(result.metadata.version_info).length > 0 && (
                    <>
                      <Typography variant="subtitle2" gutterBottom sx={{ mt: 2 }}>Version Information</Typography>
                      <List dense>
                        {Object.entries(result.metadata.version_info).slice(0, 5).map(([key, value]) => (
                          <ListItem key={key} sx={{ py: 0 }}>
                            <ListItemText 
                              primary={<><strong>{key}:</strong> {String(value)}</>}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </>
                  )}
                </Paper>
                
                {/* Capabilities based on imports */}
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.secondary.main, 0.05) }}>
                  <Typography variant="h6" gutterBottom>Detected Capabilities</Typography>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    Based on imported functions, this binary appears to have the following capabilities:
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {(result.imports || []).some(i => i?.library?.toLowerCase().includes('ws2') || i?.name?.toLowerCase().includes('socket')) && (
                      <Chip label="🌐 Network Communication" variant="outlined" />
                    )}
                    {(result.imports || []).some(i => i?.name?.toLowerCase().includes('createfile') || i?.name?.toLowerCase().includes('writefile')) && (
                      <Chip label="📁 File Operations" variant="outlined" />
                    )}
                    {(result.imports || []).some(i => i?.name?.toLowerCase().includes('regopen') || i?.name?.toLowerCase().includes('regset')) && (
                      <Chip label="🔧 Registry Access" variant="outlined" />
                    )}
                    {(result.imports || []).some(i => i?.name?.toLowerCase().includes('createprocess') || i?.name?.toLowerCase().includes('shellexecute')) && (
                      <Chip label="⚙️ Process Management" variant="outlined" />
                    )}
                    {(result.imports || []).some(i => i?.name?.toLowerCase().includes('crypt') || i?.name?.toLowerCase().includes('aes') || i?.name?.toLowerCase().includes('rsa')) && (
                      <Chip label="🔐 Cryptography" variant="outlined" />
                    )}
                    {(result.imports || []).some(i => i?.library?.toLowerCase().includes('gdi') || i?.library?.toLowerCase().includes('user32')) && (
                      <Chip label="🖥️ GUI/User Interface" variant="outlined" />
                    )}
                  </Box>
                </Paper>
              </Box>
            )
          )}
          
          {/* Tab 1: Security Findings */}
          {activeTab === 1 && (
            <Box>
              {/* For legitimate software, show security posture instead of vulnerability report */}
              {result.is_legitimate_software && securityReport ? (
                <>
                  <Alert severity="success" icon={<CheckIcon />} sx={{ mb: 2 }}>
                    <strong>Legitimate Software Detected</strong> - This binary is from a known, trusted publisher. 
                    The assessment below focuses on security posture rather than false-positive vulnerability findings.
                  </Alert>
                  {result.legitimacy_indicators && result.legitimacy_indicators.length > 0 && (
                    <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.success.main, 0.05), border: `1px solid ${alpha(theme.palette.success.main, 0.3)}` }}>
                      <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <CheckIcon color="success" fontSize="small" /> Why This Is Trusted
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {result.legitimacy_indicators.map((indicator, idx) => (
                          <Chip key={idx} label={indicator} size="small" color="success" variant="outlined" />
                        ))}
                      </Box>
                    </Paper>
                  )}
                  <Box 
                    sx={htmlContentStyles} 
                    dangerouslySetInnerHTML={{ __html: formatMarkdownContent(securityReport) }} 
                  />
                </>
              ) : securityReport ? (
                <>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    This security assessment identifies vulnerabilities, risks, and provides prioritized remediation recommendations.
                  </Alert>
                  <Box 
                    sx={htmlContentStyles} 
                    dangerouslySetInnerHTML={{ __html: formatMarkdownContent(securityReport) }} 
                  />
                </>
              ) : displayFindings.length > 0 ? (
                <>
                  <Alert severity={severityCounts.critical > 0 ? "error" : severityCounts.high > 0 ? "warning" : "info"} sx={{ mb: 2 }}>
                    Found {displayFindings.length} security findings. 
                    {verificationResult?.summary?.filtered_total 
                      ? ` AI verification filtered ${verificationResult.summary.filtered_total} false positives.`
                      : ' Review each finding for exploitability.'}
                  </Alert>
                  
                  {/* Attack Chains */}
                  {verificationResult?.attack_chains && verificationResult.attack_chains.length > 0 && (
                    <Paper sx={{ p: 2, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.1), border: `1px solid ${theme.palette.error.main}` }}>
                      <Typography variant="h6" color="error" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        ⛓️ Attack Chains Detected
                      </Typography>
                      {verificationResult.attack_chains.map((chain: any, idx: number) => (
                        <Box key={idx} sx={{ mb: 2, p: 1, bgcolor: alpha(theme.palette.background.paper, 0.5), borderRadius: 1 }}>
                          <Typography variant="subtitle2">{chain.name || `Chain ${idx + 1}`}</Typography>
                          <Typography variant="body2" color="text.secondary">{chain.description}</Typography>
                        </Box>
                      ))}
                    </Paper>
                  )}
                  
                  {/* Findings List */}
                  {displayFindings.map((finding: any, idx: number) => (
                    <Accordion key={idx} defaultExpanded={idx < 3 && finding.severity?.toLowerCase() === 'critical'}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                          <Chip 
                            label={finding.severity || 'INFO'} 
                            size="small"
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(finding.severity), 0.2),
                              color: getSeverityColor(finding.severity),
                              fontWeight: 600,
                              minWidth: 70
                            }}
                          />
                          <Typography variant="subtitle2" sx={{ flexGrow: 1 }}>
                            {finding.title || finding.category || 'Security Finding'}
                          </Typography>
                          {finding.cwe_id && (
                            <Chip label={finding.cwe_id} size="small" variant="outlined" />
                          )}
                          {finding.cve_id && (
                            <Chip label={finding.cve_id} size="small" color="error" variant="outlined" />
                          )}
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Typography variant="body2" paragraph>
                          {finding.description}
                        </Typography>
                        {finding.function_name && (
                          <Typography variant="body2" sx={{ fontFamily: "monospace", mb: 1 }}>
                            📍 Location: <code>{finding.function_name}</code>
                          </Typography>
                        )}
                        {finding.evidence && (
                          <Paper sx={{ p: 1, mb: 2, bgcolor: alpha(theme.palette.grey[900], 0.5) }}>
                            <Typography variant="caption" color="text.secondary">Evidence:</Typography>
                            <Typography variant="body2" sx={{ fontFamily: "monospace", whiteSpace: "pre-wrap" }}>
                              {finding.evidence}
                            </Typography>
                          </Paper>
                        )}
                        {finding.remediation && (
                          <Alert severity="success" sx={{ mt: 1 }}>
                            <Typography variant="body2"><strong>Remediation:</strong> {finding.remediation}</Typography>
                          </Alert>
                        )}
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </>
              ) : (
                <Alert severity="success">
                  No security vulnerabilities detected! The binary passed all automated security checks.
                </Alert>
              )}
            </Box>
          )}
          
          {/* Tab 2: Architecture Diagram */}
          {activeTab === 2 && (
            result.ai_architecture_diagram ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  This diagram shows the binary's internal architecture, data flow, and component relationships.
                </Alert>
                <ErrorBoundary fallback={<Alert severity="warning">Architecture diagram failed to render. The diagram syntax may be invalid.</Alert>}>
                  <MermaidDiagram code={result.ai_architecture_diagram} />
                </ErrorBoundary>
              </Box>
            ) : (
              <Alert severity="info">
                Architecture diagram not available. Enable AI reports during scanning to generate architectural visualizations.
              </Alert>
            )
          )}
          
          {/* Tab 3: Attack Surface Map */}
          {activeTab === 3 && (
            result.ai_attack_surface_map && result.ai_attack_surface_map.trim() ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="body2" sx={{ mb: 0.75 }}>
                    Read this map top-to-bottom: external input enters, code processes it, trust boundaries are crossed,
                    weaknesses appear, and mitigations reduce risk.
                  </Typography>
                  <Typography variant="caption">
                    Shorthand legend: E = Entry, P = Processing, W = Weakness, B = Boundary, I = Impact, M = Mitigation.
                  </Typography>
                </Alert>
                <ErrorBoundary fallback={<Alert severity="warning">Attack surface diagram failed to render. View the code below.</Alert>}>
                  <MermaidDiagram code={result.ai_attack_surface_map} />
                </ErrorBoundary>
              </Box>
            ) : attackSurface ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Attack surface analysis based on entry points and dangerous function usage.
                </Alert>
                
                {/* Attack Surface Summary */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="primary">{attackSurface.summary?.total_entry_points || 0}</Typography>
                      <Typography variant="caption">Entry Points</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="warning.main">{attackSurface.summary?.total_dangerous_functions || 0}</Typography>
                      <Typography variant="caption">Dangerous Functions</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={4}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="error">{attackSurface.summary?.total_attack_vectors || 0}</Typography>
                      <Typography variant="caption">Attack Vectors</Typography>
                    </Paper>
                  </Grid>
                </Grid>
                
                {/* Entry Points */}
                {attackSurface.entry_points && attackSurface.entry_points.length > 0 && (
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography>Entry Points ({attackSurface.entry_points.length})</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {attackSurface.entry_points.slice(0, 20).map((ep: any, idx: number) => (
                          <ListItem key={idx}>
                            <ListItemText 
                              primary={ep.name}
                              secondary={`${ep.type} @ ${ep.address}`}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}
                
                {/* Dangerous Functions */}
                {attackSurface.dangerous_functions && attackSurface.dangerous_functions.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography>Dangerous Functions ({attackSurface.dangerous_functions.length})</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {attackSurface.dangerous_functions.slice(0, 20).map((df: any, idx: number) => (
                          <ListItem key={idx}>
                            <ListItemIcon>
                              <Chip 
                                label={df.risk} 
                                size="small" 
                                color={df.risk === 'high' ? 'error' : df.risk === 'medium' ? 'warning' : 'default'}
                              />
                            </ListItemIcon>
                            <ListItemText 
                              primary={df.name}
                              secondary={df.category}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}
              </Box>
            ) : (
              <Alert severity="info">
                Attack surface map not available. Enable AI reports during scanning to generate attack visualizations.
              </Alert>
            )
          )}

          {/* Tab 4: Entropy Analysis */}
          {activeTab === 4 && (
            result.entropy_analysis ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  Entropy analysis measures randomness in the binary. High entropy (&gt;7.0) indicates encryption or packing.
                  Low entropy (&lt;2.0) indicates sparse/empty data.
                </Alert>

                {/* Summary Cards */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color={
                        result.entropy_analysis.overall_entropy > 7.0 ? "error" :
                        result.entropy_analysis.overall_entropy > 6.0 ? "warning.main" : "success.main"
                      }>
                        {result.entropy_analysis.overall_entropy.toFixed(2)}
                      </Typography>
                      <Typography variant="caption">Overall Entropy (0-8)</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color={result.entropy_analysis.is_likely_packed ? "error" : "success.main"}>
                        {result.entropy_analysis.is_likely_packed ? "Yes" : "No"}
                      </Typography>
                      <Typography variant="caption">Likely Packed</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="primary">
                        {Math.round(result.entropy_analysis.packing_confidence * 100)}%
                      </Typography>
                      <Typography variant="caption">Packing Confidence</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="secondary">
                        {result.entropy_analysis.detected_packers.length || 0}
                      </Typography>
                      <Typography variant="caption">Detected Packers</Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Detected Packers */}
                {result.entropy_analysis.detected_packers.length > 0 && (
                  <Alert severity="warning" sx={{ mb: 2 }}>
                    <strong>Detected packers/protectors:</strong>{" "}
                    {result.entropy_analysis.detected_packers.join(", ")}
                  </Alert>
                )}

                {/* Per-Section Entropy Heatmap */}
                {result.entropy_analysis.section_entropy && result.entropy_analysis.section_entropy.length > 0 && (
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Section Entropy Heatmap</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {result.entropy_analysis.section_entropy.map((section: any, idx: number) => {
                          const entropy = section.entropy || 0;
                          const pct = (entropy / 8) * 100;
                          // Color gradient: green (low) -> yellow (medium) -> red (high)
                          const r = entropy > 4 ? 255 : Math.round((entropy / 4) * 255);
                          const g = entropy < 4 ? 200 : Math.round((1 - (entropy - 4) / 4) * 200);
                          const barColor = `rgb(${r}, ${g}, 50)`;
                          return (
                            <Box key={idx} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Typography
                                variant="body2"
                                sx={{ width: 120, fontFamily: "monospace", flexShrink: 0, overflow: "hidden", textOverflow: "ellipsis" }}
                                title={section.name}
                              >
                                {section.name || "(unnamed)"}
                              </Typography>
                              <Box sx={{ flex: 1, bgcolor: alpha(theme.palette.divider, 0.2), borderRadius: 1, height: 24, position: "relative" }}>
                                <Box
                                  sx={{
                                    width: `${pct}%`,
                                    height: "100%",
                                    bgcolor: barColor,
                                    borderRadius: 1,
                                    transition: "width 0.3s ease",
                                    minWidth: 2,
                                  }}
                                />
                                <Typography
                                  variant="caption"
                                  sx={{
                                    position: "absolute",
                                    top: "50%",
                                    left: 8,
                                    transform: "translateY(-50%)",
                                    fontWeight: "bold",
                                    color: pct > 50 ? "#fff" : "text.primary",
                                    textShadow: pct > 50 ? "0 1px 2px rgba(0,0,0,0.5)" : "none",
                                  }}
                                >
                                  {entropy.toFixed(2)}
                                </Typography>
                              </Box>
                              <Typography variant="caption" sx={{ width: 80, textAlign: "right", flexShrink: 0 }}>
                                {section.raw_size ? `${(section.raw_size / 1024).toFixed(1)} KB` : ""}
                              </Typography>
                            </Box>
                          );
                        })}
                      </Box>
                      <Box sx={{ mt: 2, display: "flex", gap: 2, justifyContent: "center" }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Box sx={{ width: 16, height: 16, bgcolor: "rgb(0, 200, 50)", borderRadius: 0.5 }} />
                          <Typography variant="caption">Low (code/data)</Typography>
                        </Box>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Box sx={{ width: 16, height: 16, bgcolor: "rgb(255, 200, 50)", borderRadius: 0.5 }} />
                          <Typography variant="caption">Medium (compressed)</Typography>
                        </Box>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Box sx={{ width: 16, height: 16, bgcolor: "rgb(255, 0, 50)", borderRadius: 0.5 }} />
                          <Typography variant="caption">High (encrypted/packed)</Typography>
                        </Box>
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Entropy Regions */}
                {result.entropy_analysis.regions && result.entropy_analysis.regions.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Entropy Regions ({result.entropy_analysis.regions.length})</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {result.entropy_analysis.regions.map((region: any, idx: number) => (
                          <ListItem key={idx}>
                            <ListItemIcon>
                              <Chip
                                label={region.classification}
                                size="small"
                                color={
                                  region.classification === "packed" || region.classification === "encrypted" ? "error" :
                                  region.classification === "code" ? "primary" :
                                  region.classification === "sparse" ? "default" : "warning"
                                }
                              />
                            </ListItemIcon>
                            <ListItemText
                              primary={`0x${region.start.toString(16)} - 0x${region.end.toString(16)}${region.section_name ? ` (${region.section_name})` : ""}`}
                              secondary={`${region.description} | Avg: ${region.avg_entropy.toFixed(2)}, Max: ${region.max_entropy.toFixed(2)}`}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Entropy Sparkline (text-based) */}
                {result.entropy_analysis.entropy_data && result.entropy_analysis.entropy_data.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Entropy Distribution (File Offset)</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{
                        display: "flex",
                        height: 80,
                        alignItems: "flex-end",
                        gap: "1px",
                        bgcolor: alpha(theme.palette.divider, 0.1),
                        borderRadius: 1,
                        p: 1,
                        overflow: "hidden",
                      }}>
                        {result.entropy_analysis.entropy_data.map((point: any, idx: number) => {
                          const h = (point.entropy / 8) * 100;
                          const r = point.entropy > 4 ? 255 : Math.round((point.entropy / 4) * 255);
                          const g = point.entropy < 4 ? 200 : Math.round((1 - (point.entropy - 4) / 4) * 200);
                          return (
                            <Tooltip key={idx} title={`Offset 0x${point.offset.toString(16)}: ${point.entropy.toFixed(2)} bits/byte`}>
                              <Box
                                sx={{
                                  flex: 1,
                                  minWidth: 1,
                                  maxWidth: 8,
                                  height: `${h}%`,
                                  bgcolor: `rgb(${r}, ${g}, 50)`,
                                  borderRadius: "1px 1px 0 0",
                                  transition: "height 0.2s ease",
                                  "&:hover": { opacity: 0.8 },
                                }}
                              />
                            </Tooltip>
                          );
                        })}
                      </Box>
                      <Box sx={{ display: "flex", justifyContent: "space-between", mt: 0.5 }}>
                        <Typography variant="caption" color="text.secondary">
                          0x{result.entropy_analysis.entropy_data[0]?.offset.toString(16) || "0"}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">File Offset</Typography>
                        <Typography variant="caption" color="text.secondary">
                          0x{result.entropy_analysis.entropy_data[result.entropy_analysis.entropy_data.length - 1]?.offset.toString(16) || "0"}
                        </Typography>
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Analysis Notes */}
                {result.entropy_analysis.analysis_notes && result.entropy_analysis.analysis_notes.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Analysis Notes</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <List dense>
                        {result.entropy_analysis.analysis_notes.map((note: string, idx: number) => (
                          <ListItem key={idx}>
                            <ListItemIcon><InfoIcon fontSize="small" /></ListItemIcon>
                            <ListItemText primary={note} />
                          </ListItem>
                        ))}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                )}
              </Box>
            ) : (
              <Alert severity="info">
                Entropy analysis not available for this binary. This may occur for very small files or unsupported formats.
              </Alert>
            )
          )}

          {/* Tab 5: Symbolic Execution */}
          {activeTab === 5 && (
            result.symbolic_execution ? (
              <Box>
                <Alert severity={result.symbolic_execution.error && !result.symbolic_execution.vulnerabilities_found?.length ? "warning" : "info"} sx={{ mb: 2 }}>
                  {result.symbolic_execution.error && !result.symbolic_execution.vulnerabilities_found?.length
                    ? result.symbolic_execution.error
                    : "Symbolic execution explores program paths to discover inputs that trigger vulnerabilities, reach dangerous functions, or cause crashes."}
                </Alert>

                {/* Summary Cards */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="primary">
                        {result.symbolic_execution.paths_explored}
                      </Typography>
                      <Typography variant="caption">Paths Explored</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color={result.symbolic_execution.vulnerabilities_found?.length ? "error" : "success.main"}>
                        {result.symbolic_execution.vulnerabilities_found?.length || 0}
                      </Typography>
                      <Typography variant="caption">Vulnerabilities Found</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color={result.symbolic_execution.crash_inputs?.length ? "warning.main" : "success.main"}>
                        {result.symbolic_execution.crash_inputs?.length || 0}
                      </Typography>
                      <Typography variant="caption">Crash Inputs</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={3}>
                    <Paper sx={{ p: 2, textAlign: "center" }}>
                      <Typography variant="h4" color="secondary">
                        {result.symbolic_execution.target_reaches?.length || 0}
                      </Typography>
                      <Typography variant="caption">Targets Reached</Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Execution Stats */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={4}>
                    <Chip
                      label={`${result.symbolic_execution.execution_time_seconds?.toFixed(1) || 0}s execution time`}
                      size="small"
                      color="default"
                    />
                  </Grid>
                  <Grid item xs={4}>
                    <Chip
                      label={`Max depth: ${result.symbolic_execution.max_depth_reached || 0}`}
                      size="small"
                      color="default"
                    />
                  </Grid>
                  <Grid item xs={4}>
                    {result.symbolic_execution.timeout_reached && (
                      <Chip label="Timeout reached" size="small" color="warning" />
                    )}
                    {result.symbolic_execution.memory_used_mb > 0 && (
                      <Chip
                        label={`${result.symbolic_execution.memory_used_mb.toFixed(1)} MB used`}
                        size="small"
                        color="default"
                      />
                    )}
                  </Grid>
                </Grid>

                {/* Vulnerabilities Found */}
                {result.symbolic_execution.vulnerabilities_found && result.symbolic_execution.vulnerabilities_found.length > 0 && (
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">
                        <BugIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
                        Vulnerabilities Found ({result.symbolic_execution.vulnerabilities_found.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
                        {result.symbolic_execution.vulnerabilities_found.map((vuln: any, idx: number) => (
                          <Paper key={idx} sx={{ p: 2, border: 1, borderColor: "error.main", borderRadius: 1 }}>
                            <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 1 }}>
                              <Typography variant="subtitle2" color="error">
                                {(vuln.type || "vulnerability").replace(/_/g, " ").toUpperCase()}
                              </Typography>
                              <Box sx={{ display: "flex", gap: 1 }}>
                                {vuln.cwe && <Chip label={vuln.cwe} size="small" color="error" variant="outlined" />}
                                {vuln.function && <Chip label={vuln.function} size="small" color="warning" variant="outlined" />}
                              </Box>
                            </Box>
                            <Typography variant="body2" sx={{ mb: 1 }}>{vuln.description}</Typography>
                            {vuln.address !== undefined && vuln.address !== 0 && (
                              <Typography variant="caption" sx={{ fontFamily: "monospace" }}>
                                Address: {typeof vuln.address === "number" ? `0x${vuln.address.toString(16)}` : vuln.address}
                              </Typography>
                            )}
                            {vuln.input_sample && (
                              <Typography variant="caption" display="block" sx={{ fontFamily: "monospace", mt: 0.5 }}>
                                Input sample: {vuln.input_sample}
                              </Typography>
                            )}
                            {vuln.details && typeof vuln.details === "object" && (
                              <Box sx={{ mt: 1, p: 1, bgcolor: "action.hover", borderRadius: 1 }}>
                                {Object.entries(vuln.details).map(([key, val]: [string, any]) => (
                                  <Typography key={key} variant="caption" display="block" sx={{ fontFamily: "monospace" }}>
                                    {key}: {typeof val === "object" ? JSON.stringify(val) : String(val)}
                                  </Typography>
                                ))}
                              </Box>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Target Reaches */}
                {result.symbolic_execution.target_reaches && result.symbolic_execution.target_reaches.length > 0 && (
                  <Accordion defaultExpanded={!result.symbolic_execution.vulnerabilities_found?.length}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">
                        <PathIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
                        Dangerous Function Reachability ({result.symbolic_execution.target_reaches.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {result.symbolic_execution.target_reaches.map((tr: any, idx: number) => (
                          <Paper key={idx} sx={{ p: 1.5, display: "flex", alignItems: "center", gap: 2 }}>
                            <Chip
                              label={tr.reached ? "REACHED" : "NOT REACHED"}
                              size="small"
                              color={tr.reached ? "error" : "default"}
                            />
                            <Typography variant="body2" sx={{ fontWeight: "bold", fontFamily: "monospace" }}>
                              {tr.target_name || "unknown"}
                            </Typography>
                            <Typography variant="caption" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                              @ {tr.target_address}
                            </Typography>
                            {tr.path_length > 0 && (
                              <Chip label={`${tr.path_length} steps`} size="small" variant="outlined" />
                            )}
                            {tr.constraints_solved > 0 && (
                              <Chip label={`${tr.constraints_solved} constraints`} size="small" variant="outlined" />
                            )}
                          </Paper>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Crash Inputs */}
                {result.symbolic_execution.crash_inputs && result.symbolic_execution.crash_inputs.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">
                        <ErrorIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle", color: "warning.main" }} />
                        Crash-Inducing Inputs ({result.symbolic_execution.crash_inputs.length})
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {result.symbolic_execution.crash_inputs.map((ci: any, idx: number) => (
                          <Paper key={idx} sx={{ p: 1.5, border: 1, borderColor: "warning.main", borderRadius: 1 }}>
                            <Box sx={{ display: "flex", gap: 1, mb: 0.5 }}>
                              <Chip label={ci.crash_type} size="small" color="warning" />
                              <Chip label={ci.vulnerability_type} size="small" variant="outlined" />
                              {ci.cwe_id && <Chip label={ci.cwe_id} size="small" variant="outlined" color="error" />}
                              <Chip label={ci.exploitability} size="small" variant="outlined" />
                            </Box>
                            <Typography variant="caption" display="block" sx={{ fontFamily: "monospace" }}>
                              Type: {ci.input_type} | Crash @ {ci.crash_address}
                            </Typography>
                            {ci.input_value && (
                              <Typography variant="caption" display="block" sx={{ fontFamily: "monospace", mt: 0.5, wordBreak: "break-all" }}>
                                Input: {ci.input_value.substring(0, 128)}{ci.input_value.length > 128 ? "..." : ""}
                              </Typography>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Symbolic Inputs */}
                {result.symbolic_execution.symbolic_inputs && result.symbolic_execution.symbolic_inputs.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Symbolic Inputs Detected</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {result.symbolic_execution.symbolic_inputs.map((si: any, idx: number) => (
                          <Paper key={idx} sx={{ p: 1.5 }}>
                            <Typography variant="body2" sx={{ fontWeight: "bold" }}>
                              {si.name} ({si.type})
                              {si.size_bits > 0 && ` - ${si.size_bits} bits`}
                            </Typography>
                            {si.constraints && si.constraints.length > 0 && (
                              <Box sx={{ mt: 0.5 }}>
                                {si.constraints.map((c: string, ci2: number) => (
                                  <Typography key={ci2} variant="caption" display="block" sx={{ fontFamily: "monospace", color: "text.secondary" }}>
                                    {c}
                                  </Typography>
                                ))}
                              </Box>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}

                {/* Interesting Paths */}
                {result.symbolic_execution.interesting_paths && result.symbolic_execution.interesting_paths.length > 0 && (
                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Interesting Paths ({result.symbolic_execution.interesting_paths.length})</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                        {result.symbolic_execution.interesting_paths.map((path: any, idx: number) => (
                          <Paper key={idx} sx={{ p: 1.5, display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                            <Chip label={`Path #${path.path_id}`} size="small" />
                            <Chip label={`Depth: ${path.depth}`} size="small" variant="outlined" />
                            <Chip label={`${path.constraints_count} constraints`} size="small" variant="outlined" />
                            <Chip
                              label={path.termination_reason}
                              size="small"
                              color={path.termination_reason === "reached_target" ? "success" : "default"}
                              variant="outlined"
                            />
                            {path.is_feasible && <Chip label="Feasible" size="small" color="success" variant="outlined" />}
                          </Paper>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                )}
              </Box>
            ) : (
              <Alert severity="info">
                Symbolic execution not available for this binary. Enable symbolic execution in scan options or install angr for full support.
              </Alert>
            )
          )}
        </Box>
      </Paper>
    </Box>
  );
}

export default UnifiedBinaryResults;
