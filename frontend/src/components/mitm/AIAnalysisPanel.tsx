import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  Button,
  Paper,
  Tabs,
  Tab,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  TextField,
  IconButton,
  Tooltip,
  Alert,
  LinearProgress,
  Divider,
  Card,
  CardContent,
  Grid,
  Badge,
  CircularProgress,
  Stack,
  InputAdornment,
} from '@mui/material';
import {
  Psychology as AIIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Search as SearchIcon,
  BugReport as BugIcon,
  VpnKey as KeyIcon,
  Person as PersonIcon,
  CreditCard as CreditCardIcon,
  LocalHospital as HealthIcon,
  Code as CodeIcon,
  PlayArrow as PlayIcon,
  ContentCopy as CopyIcon,
  Refresh as RefreshIcon,
  Assessment as AssessmentIcon,
  Speed as SpeedIcon,
  QuestionAnswer as QueryIcon,
  Description as DescriptionIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';
import { mitmClient } from '../../api/client';

interface AIAnalysisPanelProps {
  proxyId: string;
  selectedEntryId?: string;
  onHighlightEntry?: (entryId: string) => void;
}

interface SensitiveDataMatch {
  data_type: string;
  field_name: string;
  value_preview: string;
  confidence: number;
  location: string;
  entry_id: string;
  risk_level: string;
  recommendation: string;
}

interface InjectionPoint {
  parameter_name: string;
  parameter_value: string;
  location: string;
  injection_types: string[];
  confidence: number;
  entry_id: string;
  reasoning: string;
  suggested_payloads: string[];
}

interface TestCase {
  id: string;
  name: string;
  description: string;
  target_entry_id: string;
  attack_type: string;
  payloads: Array<{
    position: string;
    parameter: string;
    original: string;
    payload: string;
    expected_indicator: string;
  }>;
  risk_level: string;
  prerequisites: string[];
}

interface NLQueryResult {
  query: string;
  interpretation: string;
  filter_criteria: string;
  matches: any[];
  total_matches: number;
  ai_powered: boolean;
}

interface FullAnalysisResult {
  sensitive_data: {
    matches: SensitiveDataMatch[];
    total: number;
    summary: Record<string, number>;
  };
  injection_points: {
    points: InjectionPoint[];
    total: number;
    by_type: Record<string, number>;
  };
  test_cases: {
    cases: TestCase[];
    total: number;
    by_attack_type: Record<string, number>;
  };
  traffic_analyzed: number;
  risk_score: number;
  risk_level: string;
}

const riskColors: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};

const dataTypeIcons: Record<string, React.ReactNode> = {
  credential: <KeyIcon />,
  api_key: <KeyIcon />,
  token: <SecurityIcon />,
  pii: <PersonIcon />,
  financial: <CreditCardIcon />,
  health: <HealthIcon />,
};

const injectionTypeColors: Record<string, string> = {
  sqli: '#e53935',
  xss: '#fb8c00',
  cmdi: '#d32f2f',
  xxe: '#c2185b',
  ssti: '#7b1fa2',
  path_traversal: '#5d4037',
  idor: '#1976d2',
};

const AIAnalysisPanel: React.FC<AIAnalysisPanelProps> = ({
  proxyId,
  selectedEntryId,
  onHighlightEntry,
}) => {
  const [tabValue, setTabValue] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Analysis results
  const [sensitiveData, setSensitiveData] = useState<{
    matches: SensitiveDataMatch[];
    total: number;
    summary: Record<string, number>;
  } | null>(null);
  
  const [injectionPoints, setInjectionPoints] = useState<{
    points: InjectionPoint[];
    total: number;
    by_type: Record<string, number>;
  } | null>(null);
  
  const [testCases, setTestCases] = useState<{
    cases: TestCase[];
    total: number;
    by_attack_type: Record<string, number>;
  } | null>(null);
  
  const [fullAnalysis, setFullAnalysis] = useState<FullAnalysisResult | null>(null);
  
  // NL Query
  const [nlQuery, setNlQuery] = useState('');
  const [nlResult, setNlResult] = useState<NLQueryResult | null>(null);

  // Finding Generator
  const [findingForm, setFindingForm] = useState({
    vulnerability_type: '',
    affected_endpoint: '',
    parameter: '',
    evidence: '',
    severity: 'medium',
  });
  const [generatedFinding, setGeneratedFinding] = useState<any | null>(null);

  const handleTabChange = (_: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const runFullAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/mitm/ai/full-analysis?proxy_id=${encodeURIComponent(proxyId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed: ${response.status}`);
      }
      const data = await response.json();
      setFullAnalysis(data);
      setSensitiveData(data?.sensitive_data || { matches: [], total: 0, summary: {} });
      setInjectionPoints({
        points: data?.injection_points?.points || [],
        total: data?.injection_points?.total || 0,
        by_type: data?.injection_points?.by_type || {},
      });
      setTestCases({
        cases: data?.test_cases?.cases || [],
        total: data?.test_cases?.total || 0,
        by_attack_type: data?.test_cases?.by_attack_type || {},
      });
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [proxyId]);

  const runSensitiveDataAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/mitm/ai/sensitive-data?proxy_id=${encodeURIComponent(proxyId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed: ${response.status}`);
      }
      const data = await response.json();
      setSensitiveData({
        matches: data?.matches || [],
        total: data?.total || 0,
        summary: data?.summary || { critical: 0, high: 0, medium: 0, low: 0 },
      });
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [proxyId]);

  const runInjectionAnalysis = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const url = selectedEntryId 
        ? `/api/mitm/ai/injection-points?proxy_id=${encodeURIComponent(proxyId)}&entry_id=${encodeURIComponent(selectedEntryId)}`
        : `/api/mitm/ai/injection-points?proxy_id=${encodeURIComponent(proxyId)}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Analysis failed: ${response.status}`);
      }
      const data = await response.json();
      setInjectionPoints({
        points: data?.injection_points || [],
        total: data?.total || 0,
        by_type: data?.by_type || {},
      });
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [proxyId, selectedEntryId]);

  const runTestCaseGeneration = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const url = selectedEntryId 
        ? `/api/mitm/ai/test-cases?proxy_id=${encodeURIComponent(proxyId)}&entry_id=${encodeURIComponent(selectedEntryId)}`
        : `/api/mitm/ai/test-cases?proxy_id=${encodeURIComponent(proxyId)}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Generation failed: ${response.status}`);
      }
      const data = await response.json();
      setTestCases({
        cases: data?.test_cases || [],
        total: data?.total || 0,
        by_attack_type: data?.by_attack_type || {},
      });
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [proxyId, selectedEntryId]);

  const runNLQuery = useCallback(async () => {
    if (!nlQuery.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`/api/mitm/ai/query?proxy_id=${encodeURIComponent(proxyId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: nlQuery }),
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Query failed: ${response.status}`);
      }
      const data = await response.json();
      setNlResult({
        query: data?.query || nlQuery,
        interpretation: data?.interpretation || '',
        filter_criteria: data?.filter_criteria || '',
        matches: data?.matches || [],
        total_matches: data?.total_matches || 0,
        ai_powered: data?.ai_powered || false,
      });
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [proxyId, nlQuery]);

  const generateFinding = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('/api/mitm/ai/generate-finding', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(findingForm),
      });
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `Generation failed: ${response.status}`);
      }
      const data = await response.json();
      setGeneratedFinding(data);
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  }, [findingForm]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand('copy');
      document.body.removeChild(textArea);
    });
  };

  const renderRiskScoreMeter = (score: number, level: string) => (
    <Box sx={{ mb: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
        <Typography variant="h6">Overall Risk Score</Typography>
        <Chip 
          label={`${score}/100 - ${level.toUpperCase()}`}
          color={riskColors[level] || 'default'}
          size="medium"
        />
      </Box>
      <LinearProgress 
        variant="determinate" 
        value={score} 
        color={riskColors[level] || 'primary'}
        sx={{ height: 10, borderRadius: 5 }}
      />
    </Box>
  );

  const renderSensitiveDataTab = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="subtitle1" color="text.secondary">
          Detect credentials, PII, API keys, and tokens in traffic
        </Typography>
        <Button 
          variant="contained" 
          startIcon={<SearchIcon />}
          onClick={runSensitiveDataAnalysis}
          disabled={loading}
        >
          Scan Traffic
        </Button>
      </Box>

      {sensitiveData && (
        <>
          <Grid container spacing={2} sx={{ mb: 3 }}>
            {Object.entries(sensitiveData.summary).map(([level, count]) => (
              <Grid item xs={3} key={level}>
                <Card variant="outlined">
                  <CardContent sx={{ textAlign: 'center', py: 1 }}>
                    <Typography variant="h4" color={riskColors[level] ? `${riskColors[level]}.main` : 'text.primary'}>
                      {count}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {level.toUpperCase()}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          <List sx={{ maxHeight: 400, overflow: 'auto' }}>
            {sensitiveData.matches.map((match, idx) => (
              <Paper key={idx} sx={{ mb: 1, p: 2 }} variant="outlined">
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                  {dataTypeIcons[match.data_type] || <InfoIcon />}
                  <Typography variant="subtitle2" sx={{ ml: 1, flexGrow: 1 }}>
                    {match.field_name}
                  </Typography>
                  <Chip 
                    label={match.risk_level} 
                    color={riskColors[match.risk_level]} 
                    size="small" 
                  />
                </Box>
                <Typography variant="body2" color="text.secondary">
                  Type: {match.data_type} | Location: {match.location}
                </Typography>
                <Typography variant="body2" sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', p: 0.5, mt: 1, borderRadius: 1 }}>
                  {match.value_preview}
                </Typography>
                <Alert severity="info" sx={{ mt: 1 }} icon={<InfoIcon fontSize="small" />}>
                  {match.recommendation}
                </Alert>
                <Button 
                  size="small" 
                  onClick={() => onHighlightEntry?.(match.entry_id)}
                  sx={{ mt: 1 }}
                >
                  View Request
                </Button>
              </Paper>
            ))}
            {sensitiveData.matches.length === 0 && (
              <Alert severity="success">No sensitive data exposure detected</Alert>
            )}
          </List>
        </>
      )}
    </Box>
  );

  const renderInjectionPointsTab = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="subtitle1" color="text.secondary">
          Identify SQL, XSS, command injection opportunities
        </Typography>
        <Button 
          variant="contained" 
          startIcon={<BugIcon />}
          onClick={runInjectionAnalysis}
          disabled={loading}
        >
          Find Injection Points
        </Button>
      </Box>

      {injectionPoints && (
        <>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
            {Object.entries(injectionPoints.by_type).map(([type, count]) => (
              <Chip 
                key={type}
                label={`${type.toUpperCase()}: ${count}`}
                sx={{ bgcolor: injectionTypeColors[type] || 'grey.500', color: 'white' }}
              />
            ))}
          </Box>

          <List sx={{ maxHeight: 400, overflow: 'auto' }}>
            {injectionPoints.points.map((point, idx) => (
              <Accordion key={idx} sx={{ mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', gap: 1 }}>
                    <CodeIcon color="error" />
                    <Typography sx={{ flexGrow: 1 }}>{point.parameter_name}</Typography>
                    <Chip 
                      label={`${Math.round(point.confidence * 100)}% confidence`}
                      size="small"
                      color={point.confidence > 0.7 ? 'error' : 'warning'}
                    />
                    {point.injection_types.map(type => (
                      <Chip 
                        key={type}
                        label={type}
                        size="small"
                        sx={{ bgcolor: injectionTypeColors[type], color: 'white' }}
                      />
                    ))}
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    <strong>Location:</strong> {point.location}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" gutterBottom>
                    <strong>Current Value:</strong> <code>{point.parameter_value}</code>
                  </Typography>
                  <Typography variant="body2" gutterBottom>
                    <strong>Reasoning:</strong> {point.reasoning}
                  </Typography>
                  <Divider sx={{ my: 1 }} />
                  <Typography variant="subtitle2" gutterBottom>Suggested Payloads:</Typography>
                  <Stack spacing={1}>
                    {point.suggested_payloads.map((payload, pIdx) => (
                      <Box key={pIdx} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography 
                          variant="body2" 
                          sx={{ fontFamily: 'monospace', bgcolor: 'grey.100', p: 0.5, borderRadius: 1, flexGrow: 1 }}
                        >
                          {payload}
                        </Typography>
                        <IconButton size="small" onClick={() => copyToClipboard(payload)}>
                          <CopyIcon fontSize="small" />
                        </IconButton>
                      </Box>
                    ))}
                  </Stack>
                  <Button 
                    size="small" 
                    onClick={() => onHighlightEntry?.(point.entry_id)}
                    sx={{ mt: 2 }}
                  >
                    View Original Request
                  </Button>
                </AccordionDetails>
              </Accordion>
            ))}
            {injectionPoints.points.length === 0 && (
              <Alert severity="success">No obvious injection points detected</Alert>
            )}
          </List>
        </>
      )}
    </Box>
  );

  const renderTestCasesTab = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="subtitle1" color="text.secondary">
          Auto-generate security test cases from traffic
        </Typography>
        <Button 
          variant="contained" 
          startIcon={<PlayIcon />}
          onClick={runTestCaseGeneration}
          disabled={loading}
        >
          Generate Test Cases
        </Button>
      </Box>

      {testCases && (
        <>
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
            {Object.entries(testCases.by_attack_type).map(([type, count]) => (
              <Chip 
                key={type}
                label={`${type}: ${count}`}
                variant="outlined"
              />
            ))}
          </Box>

          <List sx={{ maxHeight: 400, overflow: 'auto' }}>
            {testCases.cases.map((tc, idx) => (
              <Accordion key={idx} sx={{ mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', gap: 1 }}>
                    <BugIcon color="primary" />
                    <Typography sx={{ flexGrow: 1 }}>{tc.name}</Typography>
                    <Chip label={tc.attack_type} size="small" color="primary" variant="outlined" />
                    <Chip 
                      label={tc.risk_level}
                      size="small"
                      color={riskColors[tc.risk_level]}
                    />
                  </Box>
                </AccordionSummary>
                <AccordionDetails>
                  <Typography variant="body2" gutterBottom>{tc.description}</Typography>
                  
                  {tc.prerequisites.length > 0 && (
                    <Alert severity="info" sx={{ mb: 2 }}>
                      <strong>Prerequisites:</strong> {tc.prerequisites.join(', ')}
                    </Alert>
                  )}

                  <Typography variant="subtitle2" gutterBottom>Test Payloads:</Typography>
                  {tc.payloads.map((payload, pIdx) => (
                    <Paper key={pIdx} variant="outlined" sx={{ p: 1.5, mb: 1 }}>
                      <Grid container spacing={1}>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Parameter</Typography>
                          <Typography variant="body2">{payload.parameter} ({payload.position})</Typography>
                        </Grid>
                        <Grid item xs={6}>
                          <Typography variant="caption" color="text.secondary">Original</Typography>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{payload.original}</Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="caption" color="text.secondary">Payload</Typography>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Typography 
                              variant="body2" 
                              sx={{ fontFamily: 'monospace', bgcolor: 'error.light', color: 'error.contrastText', p: 0.5, borderRadius: 1, flexGrow: 1 }}
                            >
                              {payload.payload}
                            </Typography>
                            <IconButton size="small" onClick={() => copyToClipboard(payload.payload)}>
                              <CopyIcon fontSize="small" />
                            </IconButton>
                          </Box>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="caption" color="text.secondary">Success Indicator</Typography>
                          <Typography variant="body2" color="text.secondary">{payload.expected_indicator}</Typography>
                        </Grid>
                      </Grid>
                    </Paper>
                  ))}
                  
                  <Button 
                    size="small" 
                    onClick={() => onHighlightEntry?.(tc.target_entry_id)}
                    sx={{ mt: 1 }}
                  >
                    View Target Request
                  </Button>
                </AccordionDetails>
              </Accordion>
            ))}
            {testCases.cases.length === 0 && (
              <Alert severity="info">No test cases generated. Capture more diverse traffic.</Alert>
            )}
          </List>
        </>
      )}
    </Box>
  );

  const renderNLQueryTab = () => (
    <Box>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 2 }}>
        Query traffic using natural language
      </Typography>
      
      <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
        <TextField
          fullWidth
          variant="outlined"
          placeholder="e.g., Find all authentication requests, Show error responses, Find admin endpoints..."
          value={nlQuery}
          onChange={(e) => setNlQuery(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && runNLQuery()}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <QueryIcon />
              </InputAdornment>
            ),
          }}
        />
        <Button 
          variant="contained" 
          onClick={runNLQuery}
          disabled={loading || !nlQuery.trim()}
        >
          Query
        </Button>
      </Box>

      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 2 }}>
        {['Find all POST requests', 'Show error responses', 'Find auth requests', 'Show JSON responses', 'Find API endpoints'].map(suggestion => (
          <Chip 
            key={suggestion}
            label={suggestion}
            variant="outlined"
            onClick={() => setNlQuery(suggestion)}
            sx={{ cursor: 'pointer' }}
          />
        ))}
      </Box>

      {nlResult && (
        <Box>
          <Alert severity={nlResult.ai_powered ? 'info' : 'success'} sx={{ mb: 2 }}>
            <strong>Interpretation:</strong> {nlResult.interpretation}
            {nlResult.filter_criteria && (
              <>
                <br />
                <strong>Criteria:</strong> {nlResult.filter_criteria}
              </>
            )}
          </Alert>
          
          <Typography variant="subtitle2" gutterBottom>
            Found {nlResult.total_matches} matching entries
          </Typography>
          
          <List sx={{ maxHeight: 300, overflow: 'auto' }}>
            {nlResult.matches.slice(0, 20).map((entry: any, idx: number) => (
              <ListItem 
                key={idx}
                button
                onClick={() => onHighlightEntry?.(entry.id)}
              >
                <ListItemIcon>
                  <CheckIcon color="success" />
                </ListItemIcon>
                <ListItemText
                  primary={`${entry.request?.method} ${entry.request?.path?.substring(0, 50)}`}
                  secondary={`Status: ${entry.response?.status_code || 'N/A'}`}
                />
              </ListItem>
            ))}
          </List>
        </Box>
      )}
    </Box>
  );

  const renderFindingGeneratorTab = () => (
    <Box>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 2 }}>
        Generate professional vulnerability descriptions
      </Typography>
      
      <Grid container spacing={2}>
        <Grid item xs={6}>
          <TextField
            fullWidth
            label="Vulnerability Type"
            placeholder="e.g., SQL Injection, XSS, IDOR"
            value={findingForm.vulnerability_type}
            onChange={(e) => setFindingForm({ ...findingForm, vulnerability_type: e.target.value })}
          />
        </Grid>
        <Grid item xs={6}>
          <TextField
            fullWidth
            label="Severity"
            select
            SelectProps={{ native: true }}
            value={findingForm.severity}
            onChange={(e) => setFindingForm({ ...findingForm, severity: e.target.value })}
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </TextField>
        </Grid>
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Affected Endpoint"
            placeholder="e.g., POST /api/users/login"
            value={findingForm.affected_endpoint}
            onChange={(e) => setFindingForm({ ...findingForm, affected_endpoint: e.target.value })}
          />
        </Grid>
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Affected Parameter"
            placeholder="e.g., username, id, search"
            value={findingForm.parameter}
            onChange={(e) => setFindingForm({ ...findingForm, parameter: e.target.value })}
          />
        </Grid>
        <Grid item xs={12}>
          <TextField
            fullWidth
            multiline
            rows={3}
            label="Evidence"
            placeholder="Describe what you observed..."
            value={findingForm.evidence}
            onChange={(e) => setFindingForm({ ...findingForm, evidence: e.target.value })}
          />
        </Grid>
        <Grid item xs={12}>
          <Button 
            variant="contained" 
            startIcon={<DescriptionIcon />}
            onClick={generateFinding}
            disabled={loading || !findingForm.vulnerability_type || !findingForm.affected_endpoint}
            fullWidth
          >
            Generate Finding Description
          </Button>
        </Grid>
      </Grid>

      {generatedFinding && (
        <Paper sx={{ mt: 3, p: 2 }} variant="outlined">
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="h6">{generatedFinding.title}</Typography>
            <Chip label={generatedFinding.severity} color={riskColors[generatedFinding.severity]} />
          </Box>
          
          <Typography variant="subtitle2" gutterBottom>Description</Typography>
          <Typography variant="body2" paragraph>{generatedFinding.description}</Typography>
          
          <Typography variant="subtitle2" gutterBottom>Impact</Typography>
          <Typography variant="body2" paragraph>{generatedFinding.impact}</Typography>
          
          <Typography variant="subtitle2" gutterBottom>Remediation</Typography>
          <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }} paragraph>
            {generatedFinding.remediation}
          </Typography>
          
          {generatedFinding.references && (
            <>
              <Typography variant="subtitle2" gutterBottom>References</Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {generatedFinding.references.map((ref: string, idx: number) => (
                  <Chip key={idx} label={ref} size="small" variant="outlined" />
                ))}
              </Box>
            </>
          )}
          
          <Button 
            startIcon={<CopyIcon />}
            onClick={() => copyToClipboard(JSON.stringify(generatedFinding, null, 2))}
            sx={{ mt: 2 }}
          >
            Copy as JSON
          </Button>
        </Paper>
      )}
    </Box>
  );

  const renderOverviewTab = () => (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h6">
          <AIIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          AI Security Analysis
        </Typography>
        <Button 
          variant="contained" 
          color="primary"
          startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <AssessmentIcon />}
          onClick={runFullAnalysis}
          disabled={loading}
        >
          Run Full Analysis
        </Button>
      </Box>

      {fullAnalysis && (
        <>
          {renderRiskScoreMeter(fullAnalysis.risk_score, fullAnalysis.risk_level)}
          
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Analyzed {fullAnalysis.traffic_analyzed} traffic entries
          </Typography>

          <Grid container spacing={2}>
            <Grid item xs={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    <KeyIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'middle' }} />
                    Sensitive Data
                  </Typography>
                  <Typography variant="h4">{fullAnalysis.sensitive_data.total}</Typography>
                  <Box sx={{ mt: 1 }}>
                    {Object.entries(fullAnalysis.sensitive_data.summary).map(([level, count]) => (
                      count > 0 && <Chip key={level} label={`${level}: ${count}`} size="small" sx={{ mr: 0.5, mb: 0.5 }} color={riskColors[level]} />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    <BugIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'middle' }} />
                    Injection Points
                  </Typography>
                  <Typography variant="h4">{fullAnalysis.injection_points.total}</Typography>
                  <Box sx={{ mt: 1 }}>
                    {Object.entries(fullAnalysis.injection_points.by_type).map(([type, count]) => (
                      <Chip key={type} label={`${type}: ${count}`} size="small" sx={{ mr: 0.5, mb: 0.5 }} />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
            <Grid item xs={4}>
              <Card>
                <CardContent>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    <PlayIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: 'middle' }} />
                    Test Cases
                  </Typography>
                  <Typography variant="h4">{fullAnalysis.test_cases.total}</Typography>
                  <Box sx={{ mt: 1 }}>
                    {Object.entries(fullAnalysis.test_cases.by_attack_type).map(([type, count]) => (
                      <Chip key={type} label={`${type}: ${count}`} size="small" sx={{ mr: 0.5, mb: 0.5 }} variant="outlined" />
                    ))}
                  </Box>
                </CardContent>
              </Card>
            </Grid>
          </Grid>
        </>
      )}

      {!fullAnalysis && !loading && (
        <Alert severity="info" sx={{ mt: 2 }}>
          Click "Run Full Analysis" to scan all traffic for security issues, injection points, and generate test cases.
        </Alert>
      )}
    </Box>
  );

  return (
    <Paper sx={{ p: 2, height: '100%', display: 'flex', flexDirection: 'column' }}>
      {loading && <LinearProgress sx={{ mb: 2 }} />}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Tabs value={tabValue} onChange={handleTabChange} variant="scrollable" scrollButtons="auto" sx={{ mb: 2 }}>
        <Tab icon={<AssessmentIcon />} label="Overview" />
        <Tab icon={<KeyIcon />} label="Sensitive Data" iconPosition="start" />
        <Tab icon={<BugIcon />} label="Injection Points" iconPosition="start" />
        <Tab icon={<PlayIcon />} label="Test Cases" iconPosition="start" />
        <Tab icon={<QueryIcon />} label="NL Query" iconPosition="start" />
        <Tab icon={<DescriptionIcon />} label="Finding Generator" iconPosition="start" />
      </Tabs>

      <Box sx={{ flexGrow: 1, overflow: 'auto' }}>
        {tabValue === 0 && renderOverviewTab()}
        {tabValue === 1 && renderSensitiveDataTab()}
        {tabValue === 2 && renderInjectionPointsTab()}
        {tabValue === 3 && renderTestCasesTab()}
        {tabValue === 4 && renderNLQueryTab()}
        {tabValue === 5 && renderFindingGeneratorTab()}
      </Box>
    </Paper>
  );
};

export default AIAnalysisPanel;
