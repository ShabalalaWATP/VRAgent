/**
 * JWT Security Testing Page
 * 
 * Comprehensive JWT vulnerability scanner and attack toolkit
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Chip,
  Alert,
  AlertTitle,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tab,
  Tabs,
  IconButton,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Switch,
  FormControlLabel,
  Snackbar,
} from '@mui/material';
import {
  Security,
  BugReport,
  Key,
  Lock,
  LockOpen,
  Warning,
  Error as ErrorIcon,
  CheckCircle,
  PlayArrow,
  Stop,
  ContentCopy,
  Refresh,
  ExpandMore,
  Code,
  Visibility,
  VisibilityOff,
  Shield,
  GppBad,
  GppGood,
  Info,
  Article,
  Terminal,
  Science,
} from '@mui/icons-material';
import { useTheme, alpha } from '@mui/material/styles';

// API base URL - use relative URL for proxy routing
const API_BASE = '/api';

interface JWTAnalysis {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature_valid: boolean;
  algorithm: string;
  issues: Array<{
    severity: string;
    issue: string;
    description: string;
  }>;
  claims: {
    exp?: number;
    iat?: number;
    nbf?: number;
    iss?: string;
    sub?: string;
    aud?: string;
  };
}

interface Vulnerability {
  attack_type: string;
  vulnerability: string;
  severity: string;
  cvss_score: number;
  evidence: string;
  payload: string;
  exploitable: boolean;
  description: string;
  remediation: string;
}

interface ScanResult {
  vulnerabilities_found: number;
  vulnerabilities: Vulnerability[];
  attacks_performed: number;
  duration_ms: number;
}

interface AttackType {
  value: string;
  name: string;
  description: string;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`jwt-tabpanel-${index}`}
      aria-labelledby={`jwt-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

const JWTSecurityPage: React.FC = () => {
  const theme = useTheme();
  
  // State
  const [activeTab, setActiveTab] = useState(0);
  const [token, setToken] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [tokenLocation, setTokenLocation] = useState('header');
  const [tokenName, setTokenName] = useState('Authorization');
  const [tokenPrefix, setTokenPrefix] = useState('Bearer ');
  const [httpMethod, setHttpMethod] = useState('GET');
  const [selectedAttacks, setSelectedAttacks] = useState<string[]>([]);
  
  // Analysis state
  const [analysis, setAnalysis] = useState<JWTAnalysis | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  
  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStatus, setScanStatus] = useState('');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  
  // Forge state
  const [forgeAlgorithm, setForgeAlgorithm] = useState('none');
  const [forgeSecret, setForgeSecret] = useState('');
  const [forgePayloadMods, setForgePayloadMods] = useState('');
  const [forgedToken, setForgedToken] = useState('');
  
  // Attack types
  const [attackTypes, setAttackTypes] = useState<AttackType[]>([]);
  
  // UI state
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'info' as 'info' | 'success' | 'error' | 'warning' });
  const [showSecret, setShowSecret] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Fetch attack types on mount
  useEffect(() => {
    fetchAttackTypes();
  }, []);

  const fetchAttackTypes = async () => {
    try {
      const response = await fetch(`${API_BASE}/jwt-security/attacks`);
      const data = await response.json();
      setAttackTypes(data.attacks || []);
    } catch (error) {
      console.error('Failed to fetch attack types:', error);
    }
  };

  // Analyze JWT token
  const analyzeToken = async () => {
    if (!token.trim()) {
      setAnalysisError('Please enter a JWT token');
      return;
    }

    setIsAnalyzing(true);
    setAnalysisError(null);
    setAnalysis(null);

    try {
      const response = await fetch(`${API_BASE}/jwt-security/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token.trim() }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      if (data.success) {
        setAnalysis(data.analysis);
        setSnackbar({ open: true, message: 'Token analyzed successfully', severity: 'success' });
      } else {
        throw new Error(data.detail || 'Analysis failed');
      }
    } catch (error) {
      setAnalysisError(error instanceof Error ? error.message : 'Unknown error');
      setSnackbar({ open: true, message: 'Analysis failed', severity: 'error' });
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Start security scan
  const startScan = () => {
    if (!token.trim()) {
      setSnackbar({ open: true, message: 'Please enter a JWT token', severity: 'warning' });
      return;
    }
    if (!targetUrl.trim()) {
      setSnackbar({ open: true, message: 'Please enter a target URL', severity: 'warning' });
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanStatus('Starting scan...');
    setVulnerabilities([]);
    setScanResult(null);

    const params = new URLSearchParams();
    const body = JSON.stringify({
      token: token.trim(),
      target_url: targetUrl.trim(),
      token_location: tokenLocation,
      token_name: tokenName,
      token_prefix: tokenPrefix,
      http_method: httpMethod,
      attacks: selectedAttacks.length > 0 ? selectedAttacks : null,
    });

    // Use SSE for streaming results
    const eventSource = new EventSource(
      `${API_BASE}/jwt-security/scan?${params.toString()}`
    );
    eventSourceRef.current = eventSource;

    // Since we need POST, use fetch with SSE parsing
    fetch(`${API_BASE}/jwt-security/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    }).then(async (response) => {
      const reader = response.body?.getReader();
      const decoder = new TextDecoder();

      if (!reader) {
        throw new Error('No response body');
      }

      let buffer = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              handleScanEvent(data);
            } catch (e) {
              // Skip invalid JSON
            }
          }
        }
      }
    }).catch((error) => {
      setIsScanning(false);
      setScanStatus(`Error: ${error.message}`);
      setSnackbar({ open: true, message: `Scan failed: ${error.message}`, severity: 'error' });
    });
  };

  const handleScanEvent = (event: Record<string, unknown>) => {
    const eventType = event.type as string;

    switch (eventType) {
      case 'scan_started':
        setScanStatus('Scan initialized');
        break;
      case 'attack_started':
        setScanStatus(`Testing: ${event.attack}`);
        break;
      case 'progress':
        setScanProgress(event.progress as number);
        setScanStatus(event.message as string);
        break;
      case 'vulnerability_found':
        const vuln = event.result as Vulnerability;
        setVulnerabilities((prev) => [...prev, vuln]);
        setSnackbar({ open: true, message: `Vulnerability found: ${vuln.attack_type}`, severity: 'warning' });
        break;
      case 'attack_complete':
        setScanProgress((prev) => Math.min(prev + 10, 95));
        break;
      case 'scan_complete':
        setIsScanning(false);
        setScanProgress(100);
        setScanStatus('Scan complete');
        setScanResult(event.result as ScanResult);
        break;
      case 'error':
        setIsScanning(false);
        setScanStatus(`Error: ${event.error}`);
        setSnackbar({ open: true, message: `Scan error: ${event.error}`, severity: 'error' });
        break;
    }
  };

  const stopScan = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsScanning(false);
    setScanStatus('Scan stopped');
    setSnackbar({ open: true, message: 'Scan stopped', severity: 'info' });
  };

  // Forge JWT token
  const forgeToken = async () => {
    if (!token.trim()) {
      setSnackbar({ open: true, message: 'Please enter an original token', severity: 'warning' });
      return;
    }

    try {
      let payloadMods = {};
      if (forgePayloadMods.trim()) {
        payloadMods = JSON.parse(forgePayloadMods);
      }

      const response = await fetch(`${API_BASE}/jwt-security/forge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          original_token: token.trim(),
          payload_modifications: payloadMods,
          algorithm: forgeAlgorithm,
          secret: forgeSecret || null,
        }),
      });

      const data = await response.json();
      if (data.success) {
        setForgedToken(data.forged_token);
        setSnackbar({ open: true, message: 'Token forged successfully', severity: 'success' });
      } else {
        throw new Error(data.detail || 'Forge failed');
      }
    } catch (error) {
      setSnackbar({
        open: true,
        message: `Forge failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
        severity: 'error',
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setSnackbar({ open: true, message: 'Copied to clipboard', severity: 'info' });
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return theme.palette.error.main;
      case 'high':
        return theme.palette.warning.main;
      case 'medium':
        return theme.palette.info.main;
      case 'low':
        return theme.palette.success.main;
      default:
        return theme.palette.grey[500];
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <GppBad sx={{ color: theme.palette.error.main }} />;
      case 'high':
        return <Warning sx={{ color: theme.palette.warning.main }} />;
      case 'medium':
        return <Info sx={{ color: theme.palette.info.main }} />;
      case 'low':
        return <GppGood sx={{ color: theme.palette.success.main }} />;
      default:
        return <Security />;
    }
  };

  return (
    <Box sx={{ p: 3, maxWidth: 1400, mx: 'auto' }}>
      {/* Header */}
      <Paper
        elevation={0}
        sx={{
          p: 3,
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
          borderRadius: 2,
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Key sx={{ fontSize: 48, color: theme.palette.primary.main }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              JWT Security Testing
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Analyze, scan, and forge JSON Web Tokens to identify security vulnerabilities
            </Typography>
          </Box>
        </Box>
      </Paper>

      {/* Token Input */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Lock /> JWT Token
        </Typography>
        <TextField
          fullWidth
          multiline
          rows={3}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          sx={{ mb: 2 }}
        />
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="contained"
            startIcon={<Science />}
            onClick={analyzeToken}
            disabled={isAnalyzing || !token.trim()}
          >
            {isAnalyzing ? 'Analyzing...' : 'Analyze Token'}
          </Button>
          <Button
            variant="outlined"
            startIcon={<ContentCopy />}
            onClick={() => copyToClipboard(token)}
            disabled={!token.trim()}
          >
            Copy
          </Button>
        </Box>
      </Paper>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="fullWidth"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab icon={<Visibility />} label="Analysis" />
          <Tab icon={<BugReport />} label="Security Scan" />
          <Tab icon={<Terminal />} label="Token Forge" />
          <Tab icon={<Article />} label="Attack Info" />
        </Tabs>

        {/* Analysis Tab */}
        <TabPanel value={activeTab} index={0}>
          {analysisError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              <AlertTitle>Analysis Error</AlertTitle>
              {analysisError}
            </Alert>
          )}

          {analysis && (
            <Grid container spacing={3}>
              {/* Header */}
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Code /> Header
                    </Typography>
                    <Box
                      component="pre"
                      sx={{
                        p: 2,
                        bgcolor: 'grey.900',
                        borderRadius: 1,
                        overflow: 'auto',
                        color: 'grey.100',
                        fontSize: '0.875rem',
                      }}
                    >
                      {JSON.stringify(analysis.header, null, 2)}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              {/* Payload */}
              <Grid item xs={12} md={6}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Code /> Payload
                    </Typography>
                    <Box
                      component="pre"
                      sx={{
                        p: 2,
                        bgcolor: 'grey.900',
                        borderRadius: 1,
                        overflow: 'auto',
                        color: 'grey.100',
                        fontSize: '0.875rem',
                      }}
                    >
                      {JSON.stringify(analysis.payload, null, 2)}
                    </Box>
                  </CardContent>
                </Card>
              </Grid>

              {/* Security Issues */}
              {analysis.issues && analysis.issues.length > 0 && (
                <Grid item xs={12}>
                  <Card variant="outlined" sx={{ borderColor: 'warning.main' }}>
                    <CardContent>
                      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'warning.main' }}>
                        <Warning /> Security Issues Found
                      </Typography>
                      <List>
                        {analysis.issues.map((issue, idx) => (
                          <ListItem key={idx}>
                            <ListItemIcon>
                              {getSeverityIcon(issue.severity)}
                            </ListItemIcon>
                            <ListItemText
                              primary={issue.issue}
                              secondary={issue.description}
                            />
                            <Chip
                              label={issue.severity}
                              size="small"
                              sx={{
                                bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                                color: getSeverityColor(issue.severity),
                              }}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </CardContent>
                  </Card>
                </Grid>
              )}

              {/* Claims */}
              <Grid item xs={12}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Standard Claims
                    </Typography>
                    <Grid container spacing={2}>
                      {analysis.claims && Object.entries(analysis.claims).map(([key, value]) => (
                        value !== undefined && (
                          <Grid item xs={6} sm={4} md={3} key={key}>
                            <Typography variant="caption" color="text.secondary">
                              {key.toUpperCase()}
                            </Typography>
                            <Typography variant="body2">
                              {typeof value === 'number' && ['exp', 'iat', 'nbf'].includes(key)
                                ? new Date(value * 1000).toLocaleString()
                                : String(value)}
                            </Typography>
                          </Grid>
                        )
                      ))}
                    </Grid>
                  </CardContent>
                </Card>
              </Grid>
            </Grid>
          )}

          {!analysis && !analysisError && !isAnalyzing && (
            <Alert severity="info">
              Enter a JWT token above and click "Analyze Token" to see its structure and security issues.
            </Alert>
          )}
        </TabPanel>

        {/* Security Scan Tab */}
        <TabPanel value={activeTab} index={1}>
          <Grid container spacing={3}>
            {/* Scan Configuration */}
            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Scan Configuration
                  </Typography>
                  
                  <TextField
                    fullWidth
                    label="Target URL"
                    placeholder="https://api.example.com/protected"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    sx={{ mb: 2 }}
                  />

                  <Grid container spacing={2}>
                    <Grid item xs={6}>
                      <FormControl fullWidth size="small">
                        <InputLabel>Token Location</InputLabel>
                        <Select
                          value={tokenLocation}
                          label="Token Location"
                          onChange={(e) => setTokenLocation(e.target.value)}
                        >
                          <MenuItem value="header">Header</MenuItem>
                          <MenuItem value="cookie">Cookie</MenuItem>
                          <MenuItem value="body">Body</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                    <Grid item xs={6}>
                      <FormControl fullWidth size="small">
                        <InputLabel>HTTP Method</InputLabel>
                        <Select
                          value={httpMethod}
                          label="HTTP Method"
                          onChange={(e) => setHttpMethod(e.target.value)}
                        >
                          <MenuItem value="GET">GET</MenuItem>
                          <MenuItem value="POST">POST</MenuItem>
                          <MenuItem value="PUT">PUT</MenuItem>
                          <MenuItem value="DELETE">DELETE</MenuItem>
                        </Select>
                      </FormControl>
                    </Grid>
                  </Grid>

                  <TextField
                    fullWidth
                    label="Header/Cookie Name"
                    value={tokenName}
                    onChange={(e) => setTokenName(e.target.value)}
                    size="small"
                    sx={{ mt: 2 }}
                  />

                  <TextField
                    fullWidth
                    label="Token Prefix"
                    value={tokenPrefix}
                    onChange={(e) => setTokenPrefix(e.target.value)}
                    size="small"
                    sx={{ mt: 2 }}
                  />

                  <Box sx={{ mt: 3 }}>
                    {isScanning ? (
                      <Button
                        variant="contained"
                        color="error"
                        startIcon={<Stop />}
                        onClick={stopScan}
                        fullWidth
                      >
                        Stop Scan
                      </Button>
                    ) : (
                      <Button
                        variant="contained"
                        color="primary"
                        startIcon={<PlayArrow />}
                        onClick={startScan}
                        fullWidth
                        disabled={!token.trim() || !targetUrl.trim()}
                      >
                        Start Security Scan
                      </Button>
                    )}
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Attack Selection */}
            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Attack Types
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    Select specific attacks or leave empty to run all
                  </Typography>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, mt: 2 }}>
                    {attackTypes.map((attack) => (
                      <Chip
                        key={attack.value}
                        label={attack.name}
                        variant={selectedAttacks.includes(attack.value) ? 'filled' : 'outlined'}
                        color={selectedAttacks.includes(attack.value) ? 'primary' : 'default'}
                        onClick={() => {
                          if (selectedAttacks.includes(attack.value)) {
                            setSelectedAttacks(selectedAttacks.filter((a) => a !== attack.value));
                          } else {
                            setSelectedAttacks([...selectedAttacks, attack.value]);
                          }
                        }}
                        sx={{ cursor: 'pointer' }}
                      />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Scan Progress */}
            {(isScanning || scanResult) && (
              <Grid item xs={12}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      Scan Progress
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={scanProgress}
                      sx={{ mb: 2, height: 10, borderRadius: 5 }}
                    />
                    <Typography variant="body2" color="text.secondary">
                      {scanStatus}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            )}

            {/* Vulnerabilities Found */}
            {vulnerabilities.length > 0 && (
              <Grid item xs={12}>
                <Card variant="outlined" sx={{ borderColor: 'error.main' }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom sx={{ color: 'error.main', display: 'flex', alignItems: 'center', gap: 1 }}>
                      <GppBad /> Vulnerabilities Found ({vulnerabilities.length})
                    </Typography>
                    {vulnerabilities.map((vuln, idx) => (
                      <Accordion key={idx}>
                        <AccordionSummary expandIcon={<ExpandMore />}>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                            {getSeverityIcon(vuln.severity)}
                            <Typography sx={{ flexGrow: 1 }}>{vuln.attack_type}</Typography>
                            <Chip
                              label={`CVSS ${vuln.cvss_score}`}
                              size="small"
                              sx={{
                                bgcolor: alpha(getSeverityColor(vuln.severity), 0.2),
                                color: getSeverityColor(vuln.severity),
                              }}
                            />
                          </Box>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Typography variant="body2" paragraph>
                            {vuln.description}
                          </Typography>
                          <Typography variant="subtitle2" gutterBottom>
                            Evidence:
                          </Typography>
                          <Box
                            component="pre"
                            sx={{
                              p: 2,
                              bgcolor: 'grey.900',
                              borderRadius: 1,
                              overflow: 'auto',
                              color: 'grey.100',
                              fontSize: '0.75rem',
                              mb: 2,
                            }}
                          >
                            {vuln.evidence}
                          </Box>
                          <Typography variant="subtitle2" gutterBottom>
                            Payload:
                          </Typography>
                          <Box
                            sx={{
                              p: 2,
                              bgcolor: 'grey.100',
                              borderRadius: 1,
                              overflow: 'auto',
                              fontSize: '0.75rem',
                              mb: 2,
                            }}
                          >
                            {vuln.payload}
                          </Box>
                          <Alert severity="info">
                            <AlertTitle>Remediation</AlertTitle>
                            {vuln.remediation}
                          </Alert>
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </CardContent>
                </Card>
              </Grid>
            )}
          </Grid>
        </TabPanel>

        {/* Token Forge Tab */}
        <TabPanel value={activeTab} index={2}>
          <Alert severity="warning" sx={{ mb: 3 }}>
            <AlertTitle>⚠️ Authorized Testing Only</AlertTitle>
            Token forging should only be used for authorized security testing. Forged tokens may be detected and logged.
          </Alert>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Forge Configuration
                  </Typography>

                  <FormControl fullWidth sx={{ mb: 2 }}>
                    <InputLabel>Algorithm</InputLabel>
                    <Select
                      value={forgeAlgorithm}
                      label="Algorithm"
                      onChange={(e) => setForgeAlgorithm(e.target.value)}
                    >
                      <MenuItem value="none">None (alg=none attack)</MenuItem>
                      <MenuItem value="HS256">HS256</MenuItem>
                      <MenuItem value="HS384">HS384</MenuItem>
                      <MenuItem value="HS512">HS512</MenuItem>
                    </Select>
                  </FormControl>

                  {forgeAlgorithm.startsWith('HS') && (
                    <TextField
                      fullWidth
                      label="Secret Key"
                      type={showSecret ? 'text' : 'password'}
                      value={forgeSecret}
                      onChange={(e) => setForgeSecret(e.target.value)}
                      sx={{ mb: 2 }}
                      InputProps={{
                        endAdornment: (
                          <IconButton onClick={() => setShowSecret(!showSecret)}>
                            {showSecret ? <VisibilityOff /> : <Visibility />}
                          </IconButton>
                        ),
                      }}
                    />
                  )}

                  <TextField
                    fullWidth
                    multiline
                    rows={4}
                    label="Payload Modifications (JSON)"
                    placeholder='{"admin": true, "role": "superuser"}'
                    value={forgePayloadMods}
                    onChange={(e) => setForgePayloadMods(e.target.value)}
                    sx={{ mb: 2 }}
                  />

                  <Button
                    variant="contained"
                    startIcon={<Terminal />}
                    onClick={forgeToken}
                    fullWidth
                    disabled={!token.trim()}
                  >
                    Forge Token
                  </Button>
                </CardContent>
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card variant="outlined">
                <CardContent>
                  <Typography variant="h6" gutterBottom>
                    Forged Token
                  </Typography>
                  {forgedToken ? (
                    <>
                      <Box
                        component="pre"
                        sx={{
                          p: 2,
                          bgcolor: 'grey.900',
                          borderRadius: 1,
                          overflow: 'auto',
                          color: 'success.light',
                          fontSize: '0.75rem',
                          wordBreak: 'break-all',
                          whiteSpace: 'pre-wrap',
                        }}
                      >
                        {forgedToken}
                      </Box>
                      <Button
                        variant="outlined"
                        startIcon={<ContentCopy />}
                        onClick={() => copyToClipboard(forgedToken)}
                        sx={{ mt: 2 }}
                      >
                        Copy Forged Token
                      </Button>
                    </>
                  ) : (
                    <Typography color="text.secondary">
                      Configure options and click "Forge Token" to generate a modified JWT.
                    </Typography>
                  )}
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </TabPanel>

        {/* Attack Info Tab */}
        <TabPanel value={activeTab} index={3}>
          <Grid container spacing={3}>
            {attackTypes.map((attack) => (
              <Grid item xs={12} md={6} key={attack.value}>
                <Card variant="outlined">
                  <CardContent>
                    <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <BugReport color="primary" />
                      {attack.name}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {attack.description}
                    </Typography>
                    <Chip
                      label={attack.value}
                      size="small"
                      variant="outlined"
                      sx={{ mt: 2 }}
                    />
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </TabPanel>
      </Paper>

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar({ ...snackbar, open: false })}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default JWTSecurityPage;
