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

interface UnifiedBinaryResultsProps {
  result: BinaryAnalysisResult;
  onSaveReport?: () => void;
}

export function UnifiedBinaryResults({ result, onSaveReport }: UnifiedBinaryResultsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  
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
              <BinaryIcon color="primary" /> {result.filename}
            </Typography>
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
        </Tabs>
        
        <Box sx={{ p: 3 }}>
          {/* Tab 0: What Does This Binary Do? */}
          {activeTab === 0 && (
            result.ai_functionality_report ? (
              <Box>
                <Alert severity="info" sx={{ mb: 2 }}>
                  This report explains the binary's purpose, capabilities, and behavior based on AI analysis of its code, imports, and strings.
                </Alert>
                <Box 
                  sx={htmlContentStyles} 
                  dangerouslySetInnerHTML={{ __html: formatMarkdownContent(result.ai_functionality_report) }} 
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
              {result.is_legitimate_software && result.ai_security_report ? (
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
                    dangerouslySetInnerHTML={{ __html: formatMarkdownContent(result.ai_security_report) }} 
                  />
                </>
              ) : result.ai_security_report ? (
                <>
                  <Alert severity="info" sx={{ mb: 2 }}>
                    This security assessment identifies vulnerabilities, risks, and provides prioritized remediation recommendations.
                  </Alert>
                  <Box 
                    sx={htmlContentStyles} 
                    dangerouslySetInnerHTML={{ __html: formatMarkdownContent(result.ai_security_report) }} 
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
                  This attack tree visualizes potential attack vectors, entry points, and exploitation paths.
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
        </Box>
      </Paper>
    </Box>
  );
}

export default UnifiedBinaryResults;
