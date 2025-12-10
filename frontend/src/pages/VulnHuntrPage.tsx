import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Button,
  TextField,
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
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  IconButton,
  Tooltip,
  Stack,
} from '@mui/material';
import {
  BugReport,
  ExpandMore,
  Search,
  Security,
  Code,
  Warning,
  CheckCircle,
  PlayArrow,
  DataObject,
  CallSplit,
  Timeline,
  Description,
  ContentCopy,
  Refresh,
  Download,
  FilterList,
} from '@mui/icons-material';
import { 
  apiClient, 
  VulnHuntrResponse, 
  VulnHuntrQuickResponse, 
  VulnHuntrPatterns,
  VulnHuntrVulnerabilityFlow,
  VulnHuntrCallChainNode 
} from '../api/client';

const severityColors: Record<string, string> = {
  critical: '#d32f2f',
  high: '#f44336',
  medium: '#ff9800',
  low: '#2196f3',
  info: '#9e9e9e',
};

const severityOrder = ['critical', 'high', 'medium', 'low'];

const VulnHuntrPage: React.FC = () => {
  const [projectPath, setProjectPath] = useState('/app');
  const [codeSnippet, setCodeSnippet] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanResult, setScanResult] = useState<VulnHuntrResponse | null>(null);
  const [quickResult, setQuickResult] = useState<VulnHuntrQuickResponse | null>(null);
  const [patterns, setPatterns] = useState<VulnHuntrPatterns | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string[]>(severityOrder);
  const [expandedVuln, setExpandedVuln] = useState<string | false>(false);

  // Load patterns on mount
  React.useEffect(() => {
    fetchPatterns();
  }, []);

  const fetchPatterns = async () => {
    try {
      const data = await apiClient.vulnhuntrGetPatterns();
      setPatterns(data);
    } catch (err) {
      console.error('Failed to load patterns:', err);
    }
  };

  const runProjectScan = useCallback(async () => {
    if (!projectPath.trim()) {
      setError('Please enter a project path');
      return;
    }

    setIsScanning(true);
    setError(null);
    setScanResult(null);

    try {
      const data = await apiClient.vulnhuntrAnalyze({
        project_path: projectPath,
        file_extensions: ['.py'],
        max_files: 500,
        deep_analysis: true,
      });
      setScanResult(data);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to run VulnHuntr scan';
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  }, [projectPath]);

  const runQuickScan = useCallback(async () => {
    if (!codeSnippet.trim()) {
      setError('Please enter code to scan');
      return;
    }

    setIsScanning(true);
    setError(null);
    setQuickResult(null);

    try {
      const data = await apiClient.vulnhuntrQuickScan(codeSnippet, 'snippet.py', 'python');
      setQuickResult(data);
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to run quick scan';
      setError(errorMessage);
    } finally {
      setIsScanning(false);
    }
  }, [codeSnippet]);

  const downloadReport = useCallback(async () => {
    if (!scanResult?.scan_id) return;
    try {
      const blob = await apiClient.vulnhuntrDownloadMarkdown(scanResult.scan_id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vulnhuntr_${scanResult.scan_id}.md`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError('Failed to download report');
    }
  }, [scanResult]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const filteredVulnerabilities = (scanResult?.vulnerabilities || quickResult?.vulnerabilities || [])
    .filter((v) => severityFilter.includes(v.severity.toLowerCase()));

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

  const renderCallChain = (chain: VulnHuntrCallChainNode[]) => (
    <Box sx={{ mt: 2 }}>
      <Typography variant="subtitle2" color="primary" gutterBottom>
        <Timeline sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
        Data Flow Chain ({chain.length} steps)
      </Typography>
      <List dense sx={{ bgcolor: 'background.paper', borderRadius: 1 }}>
        {chain.map((node, index) => (
          <React.Fragment key={index}>
            <ListItem>
              <ListItemIcon>
                <CallSplit color="primary" />
              </ListItemIcon>
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Typography variant="body2" color="text.secondary">
                      {index + 1}.
                    </Typography>
                    <Typography variant="body2" fontFamily="monospace">
                      {node.file_path}:{node.line_number}
                    </Typography>
                    {node.function_name && (
                      <Chip label={node.function_name} size="small" variant="outlined" />
                    )}
                  </Box>
                }
                secondary={
                  <Box sx={{ mt: 0.5 }}>
                    <Typography
                      variant="body2"
                      component="pre"
                      sx={{
                        bgcolor: 'grey.900',
                        color: 'grey.100',
                        p: 1,
                        borderRadius: 1,
                        overflow: 'auto',
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                      }}
                    >
                      {node.code_snippet}
                    </Typography>
                    {node.transformation && (
                      <Typography variant="caption" color="text.secondary">
                        {node.transformation}
                      </Typography>
                    )}
                  </Box>
                }
              />
            </ListItem>
            {index < chain.length - 1 && <Divider variant="inset" component="li" />}
          </React.Fragment>
        ))}
      </List>
    </Box>
  );

  const renderVulnerability = (vuln: VulnHuntrVulnerabilityFlow) => (
    <Accordion
      key={vuln.id}
      expanded={expandedVuln === vuln.id}
      onChange={(_, expanded) => setExpandedVuln(expanded ? vuln.id : false)}
      sx={{ mb: 1, '&:before': { display: 'none' } }}
    >
      <AccordionSummary
        expandIcon={<ExpandMore />}
        sx={{
          borderLeft: `4px solid ${severityColors[vuln.severity.toLowerCase()]}`,
          bgcolor: 'background.paper',
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
      <AccordionDetails sx={{ bgcolor: 'grey.50' }}>
        <Grid container spacing={2}>
          {/* Source */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }} variant="outlined">
              <Typography variant="subtitle2" color="success.main" gutterBottom>
                <DataObject sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                SOURCE (User Input)
              </Typography>
              <Chip label={vuln.source.source_type} size="small" sx={{ mb: 1 }} />
              <Typography variant="body2" fontFamily="monospace">
                {vuln.source.file_path}:{vuln.source.line_number}
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Variable: <code>{vuln.source.variable_name}</code>
              </Typography>
              <Box
                component="pre"
                sx={{
                  bgcolor: 'grey.900',
                  color: 'grey.100',
                  p: 1,
                  borderRadius: 1,
                  overflow: 'auto',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                }}
              >
                {vuln.source.code_snippet}
              </Box>
            </Paper>
          </Grid>

          {/* Sink */}
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2 }} variant="outlined">
              <Typography variant="subtitle2" color="error.main" gutterBottom>
                <Warning sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                SINK (Dangerous Function)
              </Typography>
              <Chip label={vuln.sink.sink_type} size="small" sx={{ mb: 1 }} />
              <Typography variant="body2" fontFamily="monospace">
                {vuln.sink.file_path}:{vuln.sink.line_number}
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Function: <code>{vuln.sink.function_name}</code>
              </Typography>
              <Box
                component="pre"
                sx={{
                  bgcolor: 'grey.900',
                  color: 'grey.100',
                  p: 1,
                  borderRadius: 1,
                  overflow: 'auto',
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                }}
              >
                {vuln.sink.code_snippet}
              </Box>
            </Paper>
          </Grid>

          {/* Description */}
          <Grid item xs={12}>
            <Paper sx={{ p: 2 }} variant="outlined">
              <Typography variant="subtitle2" gutterBottom>
                <Description sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                Description
              </Typography>
              <Typography variant="body2">{vuln.description}</Typography>
              <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
                <Chip label={vuln.owasp_category} size="small" variant="outlined" />
              </Box>
            </Paper>
          </Grid>

          {/* Call Chain */}
          {vuln.call_chain && vuln.call_chain.length > 0 && (
            <Grid item xs={12}>
              {renderCallChain(vuln.call_chain)}
            </Grid>
          )}

          {/* LLM Analysis */}
          {vuln.llm_analysis && (
            <Grid item xs={12}>
              <Paper sx={{ p: 2, bgcolor: vuln.llm_analysis.is_false_positive ? 'warning.light' : 'error.light' }} variant="outlined">
                <Typography variant="subtitle2" gutterBottom>
                  <Security sx={{ fontSize: 16, mr: 1, verticalAlign: 'middle' }} />
                  LLM Analysis
                  {vuln.llm_analysis.is_false_positive && (
                    <Chip label="Possible False Positive" size="small" color="warning" sx={{ ml: 1 }} />
                  )}
                </Typography>
                <Typography variant="body2" paragraph>
                  {vuln.llm_analysis.description}
                </Typography>
                {vuln.llm_analysis.exploit_scenario && (
                  <>
                    <Typography variant="subtitle2">Exploit Scenario:</Typography>
                    <Typography variant="body2" color="text.secondary" paragraph>
                      {vuln.llm_analysis.exploit_scenario}
                    </Typography>
                  </>
                )}
                {vuln.llm_analysis.sanitization_bypass && (
                  <>
                    <Typography variant="subtitle2">Sanitization Bypass:</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {vuln.llm_analysis.sanitization_bypass}
                    </Typography>
                  </>
                )}
              </Paper>
            </Grid>
          )}

          {/* Remediation */}
          <Grid item xs={12}>
            <Paper sx={{ p: 2, bgcolor: 'success.light' }} variant="outlined">
              <Typography variant="subtitle2" color="success.dark" gutterBottom>
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
      <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <BugReport fontSize="large" color="error" />
        VulnHuntr - LLM-Powered Vulnerability Hunter
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Traces user input through call chains to identify remotely exploitable vulnerabilities like
        XSS, SQL injection, LFI, RCE, and SSRF. Inspired by Protect AI's VulnHuntr.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 2 }}>
        <Tab label="Project Scan" icon={<Search />} iconPosition="start" />
        <Tab label="Quick Scan (Code)" icon={<Code />} iconPosition="start" />
        <Tab label="Patterns" icon={<FilterList />} iconPosition="start" />
      </Tabs>

      {/* Project Scan Tab */}
      {activeTab === 0 && (
        <Box>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Analyze Project
            </Typography>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={8}>
                <TextField
                  fullWidth
                  label="Project Path"
                  value={projectPath}
                  onChange={(e) => setProjectPath(e.target.value)}
                  placeholder="/path/to/your/project"
                  helperText="Enter the absolute path to the project directory"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  fullWidth
                  variant="contained"
                  color="primary"
                  startIcon={isScanning ? <CircularProgress size={20} /> : <PlayArrow />}
                  onClick={runProjectScan}
                  disabled={isScanning}
                  size="large"
                >
                  {isScanning ? 'Scanning...' : 'Run VulnHuntr Scan'}
                </Button>
              </Grid>
            </Grid>
          </Paper>

          {isScanning && (
            <Box sx={{ mb: 3 }}>
              <LinearProgress />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Analyzing code flow patterns and tracing user input to dangerous sinks...
              </Typography>
            </Box>
          )}

          {scanResult && (
            <Box>
              {/* Summary Cards */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} md={2}>
                  <Card>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {scanResult.total_files_scanned}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Files Scanned
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Card>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="success.main">
                        {scanResult.sources_found}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Input Sources
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Card>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="warning.main">
                        {scanResult.sinks_found}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Dangerous Sinks
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Card sx={{ bgcolor: severityColors.critical, color: 'white' }}>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4">{scanResult.critical_count}</Typography>
                      <Typography variant="body2">Critical</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Card sx={{ bgcolor: severityColors.high, color: 'white' }}>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4">{scanResult.high_count}</Typography>
                      <Typography variant="body2">High</Typography>
                    </CardContent>
                  </Card>
                </Grid>
                <Grid item xs={6} md={2}>
                  <Card sx={{ bgcolor: severityColors.medium, color: 'white' }}>
                    <CardContent sx={{ textAlign: 'center' }}>
                      <Typography variant="h4">{scanResult.medium_count}</Typography>
                      <Typography variant="body2">Medium</Typography>
                    </CardContent>
                  </Card>
                </Grid>
              </Grid>

              {/* Actions */}
              <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
                <Button startIcon={<Download />} onClick={downloadReport}>
                  Download Markdown Report
                </Button>
                <Button startIcon={<Refresh />} onClick={runProjectScan}>
                  Re-scan
                </Button>
              </Stack>

              {/* Filter */}
              <Box sx={{ mb: 2, display: 'flex', gap: 1, alignItems: 'center' }}>
                <Typography variant="body2">Filter by severity:</Typography>
                {severityOrder.map((sev) => (
                  <Chip
                    key={sev}
                    label={sev.toUpperCase()}
                    onClick={() => {
                      setSeverityFilter((prev) =>
                        prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]
                      );
                    }}
                    sx={{
                      bgcolor: severityFilter.includes(sev) ? severityColors[sev] : 'transparent',
                      color: severityFilter.includes(sev) ? 'white' : 'inherit',
                      border: `1px solid ${severityColors[sev]}`,
                    }}
                  />
                ))}
              </Box>

              {/* Vulnerabilities List */}
              <Typography variant="h6" gutterBottom>
                Vulnerabilities Found ({filteredVulnerabilities.length})
              </Typography>
              {filteredVulnerabilities.length === 0 ? (
                <Alert severity="success" icon={<CheckCircle />}>
                  No vulnerabilities found matching the selected filters.
                </Alert>
              ) : (
                filteredVulnerabilities.map(renderVulnerability)
              )}
            </Box>
          )}
        </Box>
      )}

      {/* Quick Scan Tab */}
      {activeTab === 1 && (
        <Box>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Typography variant="h6" gutterBottom>
              Quick Code Scan
            </Typography>
            <TextField
              fullWidth
              multiline
              rows={15}
              label="Python Code"
              value={codeSnippet}
              onChange={(e) => setCodeSnippet(e.target.value)}
              placeholder={`# Paste your Python code here
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/execute')
def execute():
    cmd = request.args.get('cmd')
    os.system(cmd)  # Vulnerable!
    return "Executed"`}
              sx={{ mb: 2, fontFamily: 'monospace' }}
            />
            <Button
              variant="contained"
              color="primary"
              startIcon={isScanning ? <CircularProgress size={20} /> : <Search />}
              onClick={runQuickScan}
              disabled={isScanning}
            >
              {isScanning ? 'Scanning...' : 'Scan Code'}
            </Button>
          </Paper>

          {quickResult && (
            <Box>
              <Alert severity={quickResult.vulnerabilities_count > 0 ? 'error' : 'success'} sx={{ mb: 2 }}>
                Found {quickResult.vulnerabilities_count} vulnerability flow(s) |{' '}
                {quickResult.sources_found} source(s) | {quickResult.sinks_found} sink(s)
              </Alert>
              {quickResult.vulnerabilities.map(renderVulnerability)}
            </Box>
          )}
        </Box>
      )}

      {/* Patterns Tab */}
      {activeTab === 2 && patterns && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom color="success.main">
                <DataObject sx={{ mr: 1, verticalAlign: 'middle' }} />
                Source Patterns (User Input)
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Source Type</TableCell>
                      <TableCell align="right">Patterns</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(patterns.sources).map(([type, count]) => (
                      <TableRow key={type}>
                        <TableCell>{type}</TableCell>
                        <TableCell align="right">{count as number}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom color="error.main">
                <Warning sx={{ mr: 1, verticalAlign: 'middle' }} />
                Sink Patterns (Dangerous Functions)
              </Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Sink Type</TableCell>
                      <TableCell>Vuln Type</TableCell>
                      <TableCell>CWE</TableCell>
                      <TableCell>Severity</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {Object.entries(patterns.sinks).map(([type, info]) => (
                      <TableRow key={type}>
                        <TableCell>{type}</TableCell>
                        <TableCell>{info.vulnerability_type}</TableCell>
                        <TableCell>
                          <Chip label={info.cwe} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>{renderSeverityChip(info.severity)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          </Grid>
          <Grid item xs={12}>
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Vulnerability Types Detected
              </Typography>
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {patterns.vulnerability_types.map((type) => (
                  <Chip key={type} label={type} icon={<BugReport />} />
                ))}
              </Box>
            </Paper>
          </Grid>
        </Grid>
      )}
    </Box>
  );
};

export default VulnHuntrPage;
