import React, { useState, useCallback, useEffect } from 'react';
import {
  Box,
  Paper,
  Button,
  Typography,
  CircularProgress,
  Chip,
  Alert,
  AlertTitle,
  Collapse,
  IconButton,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Badge,
  LinearProgress,
} from '@mui/material';
import {
  AutoAwesome as AIIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  DataObject as DataIcon,
  Schema as SchemaIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Info as InfoIcon,
  ExpandMore as ExpandMoreIcon,
  Lightbulb as SuggestionIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import { apiCollections, AIResponseAnomaly, AIResponseAnalysis } from '../api/client';

interface ResponseAnomalyAnalyzerProps {
  request: {
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
  };
  response: {
    status_code: number;
    status_text?: string;
    headers?: Record<string, string>;
    body?: string;
    response_time_ms?: number;
    response_size_bytes?: number;
  };
  autoAnalyze?: boolean;
  compact?: boolean;
}

const TYPE_ICONS: Record<string, React.ReactNode> = {
  security: <SecurityIcon />,
  performance: <SpeedIcon />,
  data: <DataIcon />,
  schema: <SchemaIcon />,
  design: <WarningIcon />,
};

const TYPE_COLORS: Record<string, string> = {
  security: '#f44336',
  performance: '#ff9800',
  data: '#2196f3',
  schema: '#9c27b0',
  design: '#607d8b',
};

const SEVERITY_ICONS: Record<string, React.ReactNode> = {
  error: <ErrorIcon />,
  warning: <WarningIcon />,
  info: <InfoIcon />,
};

const SEVERITY_COLORS: Record<string, 'error' | 'warning' | 'info'> = {
  error: 'error',
  warning: 'warning',
  info: 'info',
};

export const ResponseAnomalyAnalyzer: React.FC<ResponseAnomalyAnalyzerProps> = ({
  request,
  response,
  autoAnalyze = false,
  compact = false,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AIResponseAnalysis | null>(null);
  const [expandedAnomalies, setExpandedAnomalies] = useState<Set<number>>(new Set());

  const handleAnalyze = useCallback(async () => {
    if (!response || response.status_code === undefined) return;

    setLoading(true);
    setError(null);

    try {
      const result = await apiCollections.aiAnalyzeResponse({
        request: {
          method: request.method,
          url: request.url,
          headers: request.headers,
          body: request.body,
        },
        response: {
          status_code: response.status_code,
          status_text: response.status_text,
          headers: response.headers,
          body: response.body,
          response_time_ms: response.response_time_ms,
          response_size_bytes: response.response_size_bytes,
        },
      });

      setAnalysis(result);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze response');
    } finally {
      setLoading(false);
    }
  }, [request, response]);

  // Auto-analyze if enabled
  useEffect(() => {
    if (autoAnalyze && response && response.status_code !== undefined) {
      const timer = setTimeout(() => {
        handleAnalyze();
      }, 1000);
      return () => clearTimeout(timer);
    }
  }, [autoAnalyze, response, handleAnalyze]);

  const toggleAnomaly = useCallback((index: number) => {
    setExpandedAnomalies(prev => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  }, []);

  const canAnalyze = response && response.status_code !== undefined;

  // Compact badge view
  if (compact && analysis) {
    const errorCount = analysis.by_severity.error;
    const warningCount = analysis.by_severity.warning;
    
    if (analysis.total_count === 0) {
      return (
        <Tooltip title="No anomalies detected">
          <Chip 
            icon={<CheckCircleIcon />} 
            label="Clean" 
            size="small" 
            color="success" 
            variant="outlined"
          />
        </Tooltip>
      );
    }

    return (
      <Box sx={{ display: 'flex', gap: 0.5 }}>
        {errorCount > 0 && (
          <Chip 
            icon={<ErrorIcon />} 
            label={errorCount} 
            size="small" 
            color="error"
          />
        )}
        {warningCount > 0 && (
          <Chip 
            icon={<WarningIcon />} 
            label={warningCount} 
            size="small" 
            color="warning"
          />
        )}
        {analysis.by_severity.info > 0 && (
          <Chip 
            icon={<InfoIcon />} 
            label={analysis.by_severity.info} 
            size="small" 
            color="info"
            variant="outlined"
          />
        )}
      </Box>
    );
  }

  return (
    <Paper 
      elevation={0} 
      sx={{ 
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 2,
        overflow: 'hidden',
      }}
    >
      <Box 
        sx={{ 
          p: 2, 
          background: analysis && analysis.by_severity.error > 0
            ? 'linear-gradient(135deg, rgba(244, 67, 54, 0.1) 0%, rgba(255, 152, 0, 0.1) 100%)'
            : analysis && analysis.by_severity.warning > 0
            ? 'linear-gradient(135deg, rgba(255, 152, 0, 0.1) 0%, rgba(255, 193, 7, 0.1) 100%)'
            : 'linear-gradient(135deg, rgba(33, 150, 243, 0.1) 0%, rgba(156, 39, 176, 0.1) 100%)',
          borderBottom: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <AIIcon sx={{ color: 'primary.main' }} />
          <Typography variant="subtitle1" fontWeight={600}>
            Response Analyzer
          </Typography>
          {analysis && (
            <Box sx={{ display: 'flex', gap: 0.5, ml: 'auto' }}>
              {analysis.by_severity.error > 0 && (
                <Chip label={`${analysis.by_severity.error} errors`} size="small" color="error" />
              )}
              {analysis.by_severity.warning > 0 && (
                <Chip label={`${analysis.by_severity.warning} warnings`} size="small" color="warning" />
              )}
              {analysis.by_severity.info > 0 && (
                <Chip label={`${analysis.by_severity.info} info`} size="small" color="info" variant="outlined" />
              )}
            </Box>
          )}
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          AI-powered detection of security issues, performance concerns, and data anomalies
        </Typography>
      </Box>

      <Box sx={{ p: 2 }}>
        {/* Analyze button */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 2 }}>
          <Button
            variant="contained"
            startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <AIIcon />}
            onClick={handleAnalyze}
            disabled={loading || !canAnalyze}
          >
            Analyze Response
          </Button>
          {analysis && (
            <Button
              variant="outlined"
              size="small"
              startIcon={<RefreshIcon />}
              onClick={handleAnalyze}
              disabled={loading}
            >
              Re-analyze
            </Button>
          )}
        </Box>

        {/* Loading */}
        {loading && (
          <Box sx={{ mb: 2 }}>
            <LinearProgress />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
              AI is analyzing response for anomalies...
            </Typography>
          </Box>
        )}

        {/* Error */}
        {error && (
          <Alert 
            severity="error" 
            onClose={() => setError(null)}
            sx={{ mb: 2 }}
          >
            {error}
          </Alert>
        )}

        {/* Analysis results */}
        {analysis && (
          <Box>
            {/* Summary */}
            {analysis.total_count === 0 ? (
              <Alert severity="success" icon={<CheckCircleIcon />}>
                <AlertTitle>No Anomalies Detected</AlertTitle>
                The response looks healthy. No security issues, performance concerns, or data anomalies were found.
              </Alert>
            ) : (
              <>
                {/* Category breakdown */}
                <Box sx={{ display: 'flex', gap: 1, mb: 2, flexWrap: 'wrap' }}>
                  {Object.entries(analysis.by_type).filter(([_, count]) => count > 0).map(([type, count]) => (
                    <Chip
                      key={type}
                      icon={TYPE_ICONS[type] as any}
                      label={`${type}: ${count}`}
                      size="small"
                      sx={{ 
                        borderColor: TYPE_COLORS[type],
                        color: TYPE_COLORS[type],
                      }}
                      variant="outlined"
                    />
                  ))}
                </Box>

                {/* Anomalies list */}
                <List dense sx={{ bgcolor: 'background.default', borderRadius: 1 }}>
                  {analysis.anomalies.map((anomaly, index) => (
                    <Box key={index}>
                      <ListItem
                        onClick={() => toggleAnomaly(index)}
                        sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
                      >
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Box sx={{ color: SEVERITY_COLORS[anomaly.severity] === 'error' ? 'error.main' : SEVERITY_COLORS[anomaly.severity] === 'warning' ? 'warning.main' : 'info.main' }}>
                            {SEVERITY_ICONS[anomaly.severity]}
                          </Box>
                        </ListItemIcon>
                        <ListItemIcon sx={{ minWidth: 36 }}>
                          <Tooltip title={anomaly.type}>
                            <Box sx={{ color: TYPE_COLORS[anomaly.type] || '#666' }}>
                              {TYPE_ICONS[anomaly.type] || <WarningIcon />}
                            </Box>
                          </Tooltip>
                        </ListItemIcon>
                        <ListItemText
                          primary={anomaly.title}
                          secondary={
                            <Typography 
                              variant="caption" 
                              color="text.secondary"
                              sx={{
                                display: '-webkit-box',
                                WebkitLineClamp: expandedAnomalies.has(index) ? 'unset' : 2,
                                WebkitBoxOrient: 'vertical',
                                overflow: 'hidden',
                              }}
                            >
                              {anomaly.description}
                            </Typography>
                          }
                          primaryTypographyProps={{ 
                            variant: 'body2', 
                            fontWeight: 500,
                            color: SEVERITY_COLORS[anomaly.severity] === 'error' ? 'error' : 'inherit',
                          }}
                        />
                        <IconButton size="small">
                          <ExpandMoreIcon 
                            fontSize="small"
                            sx={{ 
                              transform: expandedAnomalies.has(index) ? 'rotate(180deg)' : 'none',
                              transition: 'transform 0.2s',
                            }}
                          />
                        </IconButton>
                      </ListItem>

                      <Collapse in={expandedAnomalies.has(index)}>
                        <Box sx={{ px: 2, pb: 2, ml: 4.5 }}>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {anomaly.description}
                          </Typography>
                          
                          {anomaly.location && (
                            <Box sx={{ mb: 1 }}>
                              <Typography variant="caption" color="text.secondary">
                                Location:
                              </Typography>
                              <Typography variant="body2" fontFamily="monospace">
                                {anomaly.location}
                              </Typography>
                            </Box>
                          )}

                          {anomaly.suggestion && (
                            <Alert severity="info" icon={<SuggestionIcon />} sx={{ mt: 1 }}>
                              <Typography variant="caption">
                                <strong>Suggestion:</strong> {anomaly.suggestion}
                              </Typography>
                            </Alert>
                          )}

                          <Box sx={{ display: 'flex', gap: 0.5, mt: 1 }}>
                            <Chip 
                              label={anomaly.type} 
                              size="small" 
                              sx={{ 
                                bgcolor: TYPE_COLORS[anomaly.type] + '20',
                                color: TYPE_COLORS[anomaly.type],
                                borderColor: TYPE_COLORS[anomaly.type],
                              }}
                              variant="outlined"
                            />
                            <Chip 
                              label={anomaly.severity} 
                              size="small" 
                              color={SEVERITY_COLORS[anomaly.severity]}
                            />
                          </Box>
                        </Box>
                      </Collapse>

                      {index < analysis.anomalies.length - 1 && <Divider />}
                    </Box>
                  ))}
                </List>
              </>
            )}
          </Box>
        )}

        {/* Empty state */}
        {!analysis && !loading && !error && (
          <Box sx={{ textAlign: 'center', py: 3, color: 'text.secondary' }}>
            <AIIcon sx={{ fontSize: 40, opacity: 0.5, mb: 1 }} />
            <Typography variant="body2">
              {canAnalyze 
                ? 'Click "Analyze Response" to detect potential issues'
                : 'Execute a request first to analyze the response'}
            </Typography>
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default ResponseAnomalyAnalyzer;
