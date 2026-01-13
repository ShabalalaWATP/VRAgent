import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  CircularProgress,
  Chip,
  Alert,
  Collapse,
  IconButton,
  LinearProgress,
  Tooltip,
  Fade,
} from '@mui/material';
import {
  AutoAwesome as AIIcon,
  Send as SendIcon,
  Close as CloseIcon,
  Lightbulb as SuggestionIcon,
  ContentCopy as CopyIcon,
  Check as CheckIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { apiCollections, AIGeneratedRequest } from '../api/client';

interface NLToRequestInputProps {
  onRequestGenerated: (request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
    bodyType: string;
  }) => void;
  baseUrl?: string;
  availableEndpoints?: string[];
  authType?: string;
  variables?: Record<string, string>;
  compact?: boolean;
}

const EXAMPLE_QUERIES = [
  "Get all users with admin role",
  "Create a new product with name and price",
  "Delete user by ID",
  "Update order status to shipped",
  "Search for items containing 'widget'",
  "Authenticate with username and password",
  "Upload a file to the server",
  "Get paginated list of orders (page 2, limit 10)",
];

export const NLToRequestInput: React.FC<NLToRequestInputProps> = ({
  onRequestGenerated,
  baseUrl,
  availableEndpoints,
  authType,
  variables,
  compact = false,
}) => {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AIGeneratedRequest | null>(null);
  const [showExamples, setShowExamples] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleGenerate = useCallback(async () => {
    if (!query.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await apiCollections.aiGenerateRequest({
        query: query.trim(),
        base_url: baseUrl,
        available_endpoints: availableEndpoints,
        auth_type: authType,
        variables,
      });

      setResult(response);
    } catch (err: any) {
      setError(err.message || 'Failed to generate request');
    } finally {
      setLoading(false);
    }
  }, [query, baseUrl, availableEndpoints, authType, variables]);

  const handleUseRequest = useCallback(() => {
    if (!result?.request) return;

    onRequestGenerated({
      method: result.request.method,
      url: result.request.url,
      headers: result.request.headers,
      body: result.request.body,
      bodyType: result.request.body_type,
    });

    // Clear after use
    setQuery('');
    setResult(null);
  }, [result, onRequestGenerated]);

  const handleExampleClick = useCallback((example: string) => {
    setQuery(example);
    setShowExamples(false);
  }, []);

  const handleCopyJson = useCallback(() => {
    if (!result?.request) return;
    navigator.clipboard.writeText(JSON.stringify(result.request, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [result]);

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'success';
    if (confidence >= 0.5) return 'warning';
    return 'error';
  };

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case 'GET': return '#61affe';
      case 'POST': return '#49cc90';
      case 'PUT': return '#fca130';
      case 'PATCH': return '#50e3c2';
      case 'DELETE': return '#f93e3e';
      default: return '#9012fe';
    }
  };

  if (compact) {
    return (
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
        <TextField
          fullWidth
          size="small"
          placeholder="Describe your API request in plain English..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && !e.shiftKey && handleGenerate()}
          disabled={loading}
          InputProps={{
            startAdornment: <AIIcon sx={{ mr: 1, color: 'primary.main' }} />,
          }}
        />
        <Button
          variant="contained"
          onClick={handleGenerate}
          disabled={loading || !query.trim()}
          sx={{ minWidth: 100 }}
        >
          {loading ? <CircularProgress size={20} /> : 'Generate'}
        </Button>
      </Box>
    );
  }

  return (
    <Paper 
      elevation={0} 
      sx={{ 
        p: 2, 
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 2,
        background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.05) 0%, rgba(168, 85, 247, 0.05) 100%)',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <AIIcon sx={{ color: 'primary.main' }} />
        <Typography variant="subtitle1" fontWeight={600}>
          AI Request Generator
        </Typography>
        <Chip 
          label="Natural Language" 
          size="small" 
          color="primary" 
          variant="outlined"
          sx={{ ml: 'auto' }}
        />
      </Box>

      <TextField
        fullWidth
        multiline
        minRows={2}
        maxRows={4}
        placeholder="Describe your API request in plain English...&#10;Example: 'Get all users with admin role' or 'Create a new product with price 19.99'"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        disabled={loading}
        sx={{ mb: 1 }}
      />

      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 2 }}>
        <Button
          variant="contained"
          startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <SendIcon />}
          onClick={handleGenerate}
          disabled={loading || !query.trim()}
        >
          Generate Request
        </Button>
        <Button
          variant="outlined"
          size="small"
          startIcon={<SuggestionIcon />}
          onClick={() => setShowExamples(!showExamples)}
        >
          Examples
        </Button>
        {result && (
          <Button
            variant="text"
            size="small"
            startIcon={<RefreshIcon />}
            onClick={() => { setResult(null); setQuery(''); }}
          >
            Clear
          </Button>
        )}
      </Box>

      {/* Example queries */}
      <Collapse in={showExamples}>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
          {EXAMPLE_QUERIES.map((example, i) => (
            <Chip
              key={i}
              label={example}
              size="small"
              variant="outlined"
              onClick={() => handleExampleClick(example)}
              sx={{ cursor: 'pointer', '&:hover': { bgcolor: 'action.hover' } }}
            />
          ))}
        </Box>
      </Collapse>

      {/* Loading indicator */}
      {loading && (
        <Box sx={{ mb: 2 }}>
          <LinearProgress />
          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
            AI is generating your request...
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

      {/* Result */}
      <Collapse in={!!result}>
        {result && (
          <Fade in>
            <Paper 
              variant="outlined" 
              sx={{ 
                p: 2, 
                bgcolor: 'background.default',
                borderRadius: 1,
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <Typography variant="subtitle2" color="text.secondary">
                  Generated Request
                </Typography>
                <Chip
                  label={`${Math.round(result.confidence * 100)}% confidence`}
                  size="small"
                  color={getConfidenceColor(result.confidence) as any}
                  sx={{ ml: 'auto' }}
                />
                <Tooltip title="Copy as JSON">
                  <IconButton size="small" onClick={handleCopyJson}>
                    {copied ? <CheckIcon fontSize="small" /> : <CopyIcon fontSize="small" />}
                  </IconButton>
                </Tooltip>
              </Box>

              {/* Method and URL */}
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                <Chip
                  label={result.request.method}
                  size="small"
                  sx={{
                    bgcolor: getMethodColor(result.request.method),
                    color: 'white',
                    fontWeight: 600,
                    minWidth: 60,
                  }}
                />
                <Typography 
                  variant="body2" 
                  fontFamily="monospace"
                  sx={{ 
                    flex: 1,
                    bgcolor: 'action.hover',
                    px: 1,
                    py: 0.5,
                    borderRadius: 0.5,
                  }}
                >
                  {result.request.url}
                </Typography>
              </Box>

              {/* Headers */}
              {Object.keys(result.request.headers || {}).length > 0 && (
                <Box sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    Headers:
                  </Typography>
                  <Box sx={{ ml: 1 }}>
                    {Object.entries(result.request.headers).map(([key, value]) => (
                      <Typography key={key} variant="caption" fontFamily="monospace" display="block">
                        {key}: {value}
                      </Typography>
                    ))}
                  </Box>
                </Box>
              )}

              {/* Body */}
              {result.request.body && (
                <Box sx={{ mb: 1 }}>
                  <Typography variant="caption" color="text.secondary">
                    Body ({result.request.body_type}):
                  </Typography>
                  <Box
                    component="pre"
                    sx={{
                      bgcolor: 'action.hover',
                      p: 1,
                      borderRadius: 0.5,
                      fontSize: '0.75rem',
                      overflow: 'auto',
                      maxHeight: 100,
                      m: 0,
                    }}
                  >
                    {result.request.body}
                  </Box>
                </Box>
              )}

              {/* Description */}
              {result.description && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {result.description}
                </Typography>
              )}

              {/* Suggestions */}
              {result.suggestions && result.suggestions.length > 0 && (
                <Alert severity="info" sx={{ mb: 2 }}>
                  <Typography variant="caption" fontWeight={600}>
                    Suggestions:
                  </Typography>
                  <ul style={{ margin: 0, paddingLeft: 20 }}>
                    {result.suggestions.map((s, i) => (
                      <li key={i}>
                        <Typography variant="caption">{s}</Typography>
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}

              {/* Actions */}
              <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={handleUseRequest}
                >
                  Use This Request
                </Button>
                <Button
                  variant="outlined"
                  onClick={handleGenerate}
                  startIcon={<RefreshIcon />}
                >
                  Regenerate
                </Button>
              </Box>
            </Paper>
          </Fade>
        )}
      </Collapse>
    </Paper>
  );
};

export default NLToRequestInput;
