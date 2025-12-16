import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Button,
  Card,
  CardContent,
  Chip,
  Alert,
  CircularProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  LinearProgress,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  IconButton,
  Tooltip,
  Stack,
  alpha,
  useTheme,
} from '@mui/material';
import {
  Psychology,
  ExpandMore,
  Security,
  Code,
  Warning,
  CheckCircle,
  PlayArrow,
  Timeline,
  Description,
  ContentCopy,
  ArrowBack,
  AutoAwesome,
  AccountTree,
  DataObject,
  CallSplit,
  Refresh,
  BugReport,
  Stop,
  Download,
} from '@mui/icons-material';
import { api } from '../api/client';
import { 
  agenticScanClient,
  AgenticScanResult,
  AgenticVulnerability,
  AgenticScanProgress,
  AgenticScanPhase,
} from '../api/client';

// Severity colors for vulnerability display
const severityColors: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f44336',
  medium: '#ff9800',
  low: '#2196f3',
  info: '#9e9e9e',
};

// Map API phase names to step index
const phaseToStepIndex: Record<AgenticScanPhase, number> = {
  initializing: 0,
  chunking: 0,
  entry_point_detection: 1,
  flow_tracing: 2,
  vulnerability_analysis: 3,
  report_generation: 4,
  complete: 5,
  error: -1,
};

// Agent analysis phases
const ANALYSIS_PHASES = [
  {
    label: 'Code Chunking',
    description: 'Breaking codebase into manageable chunks for LLM analysis',
    icon: <AccountTree />,
  },
  {
    label: 'Entry Point Detection',
    description: 'Identifying user input sources and API endpoints',
    icon: <DataObject />,
  },
  {
    label: 'Flow Tracing',
    description: 'Mapping data flow from input to output through the application',
    icon: <CallSplit />,
  },
  {
    label: 'Vulnerability Analysis',
    description: 'AI-powered detection of security vulnerabilities',
    icon: <BugReport />,
  },
  {
    label: 'Report Generation',
    description: 'Compiling findings with remediation recommendations',
    icon: <Description />,
  },
];

const AgenticAIScanPage: React.FC = () => {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const theme = useTheme();
  
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<AgenticScanResult | null>(null);
  const [progress, setProgress] = useState<AgenticScanProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activePhase, setActivePhase] = useState(0);
  const [expandedVuln, setExpandedVuln] = useState<string | false>(false);
  const [projectPath, setProjectPath] = useState<string | null>(null);
  const stopPollingRef = useRef<(() => void) | null>(null);

  // Get project path on mount
  useEffect(() => {
    const fetchProject = async () => {
      try {
        const project = await api.getProject(Number(projectId));
        // The project path is typically in git_url or we construct it
        // For demo purposes, we'll use a relative path based on project name
        const path = project.git_url || `/app/projects/${project.name}`;
        setProjectPath(path);
      } catch (err) {
        console.error('Failed to fetch project:', err);
      }
    };
    fetchProject();
  }, [projectId]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (stopPollingRef.current) {
        stopPollingRef.current();
      }
    };
  }, []);

  // Handle progress updates
  const handleProgress = useCallback((progressData: AgenticScanProgress) => {
    setProgress(progressData);
    const stepIndex = phaseToStepIndex[progressData.phase] ?? 0;
    setActivePhase(Math.max(0, stepIndex));
  }, []);

  // Handle scan completion
  const handleComplete = useCallback((result: AgenticScanResult) => {
    setScanResult(result);
    setIsScanning(false);
    setActivePhase(ANALYSIS_PHASES.length);
  }, []);

  // Handle errors
  const handleError = useCallback((errorMsg: string) => {
    setError(errorMsg);
    setIsScanning(false);
  }, []);

  // Start a new agentic scan
  const startAgenticScan = async () => {
    if (!projectPath) {
      setError('Project path not available. Please try again.');
      return;
    }

    setIsScanning(true);
    setError(null);
    setScanResult(null);
    setProgress(null);
    setActivePhase(0);
    
    try {
      // Start the scan
      const response = await agenticScanClient.startScan({
        project_id: Number(projectId),
        project_path: projectPath,
        file_extensions: ['.py', '.js', '.ts', '.jsx', '.tsx'],
      });

      // Start polling for progress
      stopPollingRef.current = agenticScanClient.pollProgress(
        response.scan_id,
        handleProgress,
        handleComplete,
        handleError,
        1500 // Poll every 1.5 seconds
      );
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to start agentic scan';
      handleError(errorMessage);
    }
  };

  // Cancel the current scan
  const cancelScan = async () => {
    if (stopPollingRef.current) {
      stopPollingRef.current();
      stopPollingRef.current = null;
    }
    
    if (progress?.scan_id) {
      try {
        await agenticScanClient.cancelScan(progress.scan_id);
      } catch (err) {
        console.error('Failed to cancel scan:', err);
      }
    }
    
    setIsScanning(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const renderSeverityChip = (severity: string) => (
    <Chip
      label={severity.toUpperCase()}
      size="small"
      sx={{
        bgcolor: severityColors[severity.toLowerCase()] || severityColors.info,
        color: 'white',
        fontWeight: 'bold',
      }}
    />
  );

  const renderVulnerability = (vuln: AgenticVulnerability) => (
    <Accordion
      key={vuln.id}
      expanded={expandedVuln === vuln.id}
      onChange={(_, expanded) => setExpandedVuln(expanded ? vuln.id : false)}
      sx={{ 
        mb: 1, 
        '&:before': { display: 'none' },
        background: alpha(theme.palette.background.paper, 0.8),
        backdropFilter: 'blur(10px)',
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMore />}
        sx={{
          borderLeft: `4px solid ${severityColors[vuln.severity.toLowerCase()]}`,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
          {renderSeverityChip(vuln.severity)}
          <BugReport color="error" />
          <Typography fontWeight="bold">{vuln.vulnerability_type}</Typography>
          <Chip label={vuln.cwe_id} size="small" variant="outlined" />
          <Typography variant="body2" color="text.secondary" sx={{ ml: 'auto', mr: 2 }}>
            Confidence: {Math.round(vuln.confidence * 100)}%
          </Typography>
        </Box>
      </AccordionSummary>
      <AccordionDetails>
        <Grid container spacing={2}>
          {/* Description */}
          <Grid item xs={12}>
            <Typography variant="subtitle2" gutterBottom>
              <Description sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
              Description
            </Typography>
            <Typography variant="body2">{vuln.description}</Typography>
          </Grid>

          {/* LLM Analysis */}
          <Grid item xs={12}>
            <Paper 
              sx={{ 
                p: 2, 
                bgcolor: alpha(theme.palette.info.main, 0.1),
                border: `1px solid ${alpha(theme.palette.info.main, 0.3)}`,
              }} 
              variant="outlined"
            >
              <Typography variant="subtitle2" gutterBottom color="info.main">
                <Psychology sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                AI Analysis
              </Typography>
              <Typography variant="body2">{vuln.llm_analysis}</Typography>
            </Paper>
          </Grid>

          {/* Exploit Scenario */}
          {vuln.exploit_scenario && (
            <Grid item xs={12}>
              <Paper 
                sx={{ 
                  p: 2, 
                  bgcolor: alpha(theme.palette.warning.main, 0.1),
                  border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                }} 
                variant="outlined"
              >
                <Typography variant="subtitle2" gutterBottom color="warning.main">
                  <Warning sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                  Exploit Scenario
                </Typography>
                <Typography variant="body2">{vuln.exploit_scenario}</Typography>
              </Paper>
            </Grid>
          )}

          {/* Remediation */}
          <Grid item xs={12}>
            <Paper 
              sx={{ 
                p: 2, 
                bgcolor: alpha(theme.palette.success.main, 0.1),
                border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
              }} 
              variant="outlined"
            >
              <Typography variant="subtitle2" gutterBottom color="success.main">
                <CheckCircle sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                Remediation
              </Typography>
              <Typography variant="body2">{vuln.remediation}</Typography>
              <Tooltip title="Copy remediation">
                <IconButton size="small" onClick={() => copyToClipboard(vuln.remediation)}>
                  <ContentCopy fontSize="small" />
                </IconButton>
              </Tooltip>
            </Paper>
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
  );

  return (
    <Box sx={{ p: 3 }}>
      {/* Header with back button */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
        <IconButton onClick={() => navigate(`/projects/${projectId}`)}>
          <ArrowBack />
        </IconButton>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 3,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`,
              boxShadow: `0 4px 20px ${alpha('#8b5cf6', 0.4)}`,
            }}
          >
            <Psychology sx={{ fontSize: 32, color: 'white' }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Agentic AI Security Scan
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Deep codebase analysis with iterative LLM-powered vulnerability detection
            </Typography>
          </Box>
        </Box>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* How it works section */}
      <Paper 
        sx={{ 
          p: 3, 
          mb: 4,
          background: `linear-gradient(135deg, ${alpha('#6366f1', 0.05)} 0%, ${alpha('#8b5cf6', 0.05)} 100%)`,
          border: `1px solid ${alpha('#8b5cf6', 0.2)}`,
        }}
      >
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <AutoAwesome sx={{ color: '#8b5cf6' }} />
          How Agentic AI Scanning Works
        </Typography>
        <Grid container spacing={2} sx={{ mt: 1 }}>
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', bgcolor: 'transparent' }}>
              <CardContent>
                <AccountTree color="primary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="subtitle1" fontWeight={600}>Code Chunking</Typography>
                <Typography variant="body2" color="text.secondary">
                  Breaks down large codebases into manageable chunks that fit within LLM context windows,
                  enabling comprehensive analysis of extensive projects.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', bgcolor: 'transparent' }}>
              <CardContent>
                <Timeline color="secondary" sx={{ fontSize: 40, mb: 1 }} />
                <Typography variant="subtitle1" fontWeight={600}>Iterative Analysis</Typography>
                <Typography variant="body2" color="text.secondary">
                  Uses prompt engineering to request additional code snippets as needed,
                  allowing the AI to map complete application flows from user input to server output.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={4}>
            <Card variant="outlined" sx={{ height: '100%', bgcolor: 'transparent' }}>
              <CardContent>
                <Security sx={{ fontSize: 40, mb: 1, color: '#10b981' }} />
                <Typography variant="subtitle1" fontWeight={600}>Deep Vulnerability Detection</Typography>
                <Typography variant="body2" color="text.secondary">
                  Reveals complex vulnerabilities that traditional static analyzers miss,
                  significantly reducing false positives through comprehensive flow analysis.
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </Paper>

      {/* Scan Control */}
      <Paper sx={{ p: 3, mb: 4 }}>
        <Grid container spacing={3} alignItems="center">
          <Grid item xs={12} md={8}>
            <Typography variant="h6" gutterBottom>
              Start Agentic Analysis
            </Typography>
            <Typography variant="body2" color="text.secondary">
              This scan performs deep AI-powered analysis by iteratively examining code chunks
              and tracing data flows through your application. The analysis may take several
              minutes depending on codebase size.
            </Typography>
          </Grid>
          <Grid item xs={12} md={4}>
            <Stack direction="row" spacing={1}>
              <Button
                fullWidth
                variant="contained"
                size="large"
                startIcon={isScanning ? <CircularProgress size={20} color="inherit" /> : <PlayArrow />}
                onClick={startAgenticScan}
                disabled={isScanning}
                sx={{
                  py: 2,
                  background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`,
                  boxShadow: `0 4px 20px ${alpha('#8b5cf6', 0.4)}`,
                  '&:hover': {
                    background: `linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%)`,
                  },
                }}
              >
                {isScanning ? 'Analyzing...' : 'Start Agentic Scan'}
              </Button>
              {isScanning && (
                <Button
                  variant="outlined"
                  color="error"
                  onClick={cancelScan}
                  startIcon={<Stop />}
                  sx={{ minWidth: 120 }}
                >
                  Cancel
                </Button>
              )}
            </Stack>
          </Grid>
        </Grid>
      </Paper>

      {/* Analysis Progress */}
      {isScanning && progress && (
        <Paper sx={{ p: 3, mb: 4 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">Analysis Progress</Typography>
            <Typography variant="body2" color="text.secondary">
              {progress.message}
            </Typography>
          </Box>
          
          {/* Progress Stats */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={3}>
              <Typography variant="caption" color="text.secondary">Chunks</Typography>
              <Typography variant="body1">{progress.analyzed_chunks} / {progress.total_chunks}</Typography>
            </Grid>
            <Grid item xs={3}>
              <Typography variant="caption" color="text.secondary">Entry Points</Typography>
              <Typography variant="body1">{progress.entry_points_found}</Typography>
            </Grid>
            <Grid item xs={3}>
              <Typography variant="caption" color="text.secondary">Flows Traced</Typography>
              <Typography variant="body1">{progress.flows_traced}</Typography>
            </Grid>
            <Grid item xs={3}>
              <Typography variant="caption" color="text.secondary">Vulnerabilities</Typography>
              <Typography variant="body1" color="error.main">{progress.vulnerabilities_found}</Typography>
            </Grid>
          </Grid>
          
          <Stepper activeStep={activePhase} orientation="vertical">
            {ANALYSIS_PHASES.map((phase, index) => (
              <Step key={phase.label}>
                <StepLabel
                  StepIconComponent={() => (
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        bgcolor: index <= activePhase 
                          ? `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`
                          : alpha(theme.palette.action.disabled, 0.2),
                        color: index <= activePhase ? 'white' : 'text.disabled',
                        background: index <= activePhase 
                          ? `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`
                          : undefined,
                      }}
                    >
                      {React.cloneElement(phase.icon, { sx: { fontSize: 18 } })}
                    </Box>
                  )}
                >
                  <Typography fontWeight={600}>{phase.label}</Typography>
                </StepLabel>
                <StepContent>
                  <Typography variant="body2" color="text.secondary">
                    {phase.description}
                  </Typography>
                  {index === activePhase && (
                    <LinearProgress 
                      sx={{ 
                        mt: 2, 
                        borderRadius: 1,
                        '& .MuiLinearProgress-bar': {
                          background: `linear-gradient(90deg, #6366f1, #8b5cf6)`,
                        },
                      }} 
                    />
                  )}
                </StepContent>
              </Step>
            ))}
          </Stepper>
        </Paper>
      )}

      {/* Scan Results */}
      {scanResult && (
        <Box>
          {/* Summary Cards */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={6} md={2}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" color="primary">
                    {scanResult.total_chunks}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Code Chunks
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={2}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" color="success.main">
                    {scanResult.entry_points_count}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Entry Points
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={2}>
              <Card>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4" color="info.main">
                    {scanResult.flows_traced}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Flows Traced
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={2}>
              <Card sx={{ bgcolor: severityColors.critical, color: 'white' }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4">
                    {scanResult.statistics?.by_severity?.critical || 0}
                  </Typography>
                  <Typography variant="body2">Critical</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={2}>
              <Card sx={{ bgcolor: severityColors.high, color: 'white' }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4">
                    {scanResult.statistics?.by_severity?.high || 0}
                  </Typography>
                  <Typography variant="body2">High</Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={6} md={2}>
              <Card sx={{ bgcolor: severityColors.medium, color: 'white' }}>
                <CardContent sx={{ textAlign: 'center' }}>
                  <Typography variant="h4">
                    {scanResult.statistics?.by_severity?.medium || 0}
                  </Typography>
                  <Typography variant="body2">Medium</Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* Actions */}
          <Stack direction="row" spacing={2} sx={{ mb: 3 }}>
            <Button startIcon={<Refresh />} onClick={startAgenticScan}>
              Re-scan
            </Button>
          </Stack>

          {/* Vulnerabilities List */}
          <Typography variant="h6" gutterBottom>
            Vulnerabilities Found ({scanResult.vulnerabilities.length})
          </Typography>
          {scanResult.vulnerabilities.length === 0 ? (
            <Alert severity="success" icon={<CheckCircle />}>
              No vulnerabilities detected. The agentic scan found no exploitable security issues.
            </Alert>
          ) : (
            scanResult.vulnerabilities.map(renderVulnerability)
          )}
        </Box>
      )}

      {/* Empty state when no scan has been run */}
      {!isScanning && !scanResult && (
        <Paper 
          sx={{ 
            p: 6, 
            textAlign: 'center',
            background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.03)} 100%)`,
            border: `2px dashed ${alpha(theme.palette.info.main, 0.3)}`,
            borderRadius: 3,
          }}
        >
          <Psychology sx={{ fontSize: 64, color: alpha('#8b5cf6', 0.5), mb: 2 }} />
          <Typography variant="h6" gutterBottom>
            Ready to Start Agentic Analysis
          </Typography>
          <Typography color="text.secondary" sx={{ maxWidth: 500, mx: 'auto', mb: 3 }}>
            This advanced scan uses iterative AI prompting to deeply analyze your codebase,
            tracing data flows and identifying complex vulnerabilities that traditional
            scanners miss.
          </Typography>
          <Button
            variant="outlined"
            startIcon={<PlayArrow />}
            onClick={startAgenticScan}
            sx={{
              borderColor: '#8b5cf6',
              color: '#8b5cf6',
              '&:hover': {
                borderColor: '#7c3aed',
                bgcolor: alpha('#8b5cf6', 0.1),
              },
            }}
          >
            Launch Agentic Scan
          </Button>
        </Paper>
      )}
    </Box>
  );
};

export default AgenticAIScanPage;
