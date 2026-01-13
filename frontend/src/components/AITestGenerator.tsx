import React, { useState, useCallback } from 'react';
import {
  Box,
  Paper,
  Button,
  Typography,
  CircularProgress,
  Chip,
  Alert,
  Collapse,
  IconButton,
  LinearProgress,
  Tooltip,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material';
import {
  Science as TestIcon,
  AutoAwesome as AIIcon,
  Check as CheckIcon,
  Close as CloseIcon,
  ContentCopy as CopyIcon,
  ExpandMore as ExpandMoreIcon,
  Code as CodeIcon,
  Speed as SpeedIcon,
  Security as SecurityIcon,
  DataObject as DataIcon,
  Warning as WarningIcon,
} from '@mui/icons-material';
import { apiCollections, AIGeneratedTest, AIGeneratedTests } from '../api/client';

interface AITestGeneratorProps {
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
  };
  onTestsGenerated?: (tests: AIGeneratedTest[]) => void;
  onTestAdded?: (test: AIGeneratedTest) => void;
}

const TEST_TYPE_ICONS: Record<string, React.ReactNode> = {
  status: <CheckIcon />,
  json_path: <DataIcon />,
  header: <SecurityIcon />,
  response_time: <SpeedIcon />,
  contains: <DataIcon />,
  schema: <DataIcon />,
};

const TEST_TYPE_COLORS: Record<string, string> = {
  status: '#49cc90',
  json_path: '#61affe',
  header: '#9012fe',
  response_time: '#fca130',
  contains: '#50e3c2',
  schema: '#f93e3e',
};

export const AITestGenerator: React.FC<AITestGeneratorProps> = ({
  request,
  response,
  onTestsGenerated,
  onTestAdded,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tests, setTests] = useState<AIGeneratedTest[]>([]);
  const [selectedTests, setSelectedTests] = useState<Set<number>>(new Set());
  const [expanded, setExpanded] = useState<number | null>(null);
  const [copied, setCopied] = useState<number | null>(null);

  const handleGenerate = useCallback(async () => {
    setLoading(true);
    setError(null);
    setTests([]);
    setSelectedTests(new Set());

    try {
      const result = await apiCollections.aiGenerateTests({
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
        },
      });

      setTests(result.tests);
      // Auto-select all tests by default
      setSelectedTests(new Set(result.tests.map((_, i) => i)));
      
      if (onTestsGenerated) {
        onTestsGenerated(result.tests);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to generate tests');
    } finally {
      setLoading(false);
    }
  }, [request, response, onTestsGenerated]);

  const handleToggleTest = useCallback((index: number) => {
    setSelectedTests(prev => {
      const next = new Set(prev);
      if (next.has(index)) {
        next.delete(index);
      } else {
        next.add(index);
      }
      return next;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (selectedTests.size === tests.length) {
      setSelectedTests(new Set());
    } else {
      setSelectedTests(new Set(tests.map((_, i) => i)));
    }
  }, [tests, selectedTests]);

  const handleCopyCode = useCallback((test: AIGeneratedTest, index: number) => {
    navigator.clipboard.writeText(test.code);
    setCopied(index);
    setTimeout(() => setCopied(null), 2000);
  }, []);

  const handleAddTest = useCallback((test: AIGeneratedTest) => {
    if (onTestAdded) {
      onTestAdded(test);
    }
  }, [onTestAdded]);

  const handleAddSelected = useCallback(() => {
    if (onTestsGenerated) {
      const selectedTestsList = tests.filter((_, i) => selectedTests.has(i));
      onTestsGenerated(selectedTestsList);
    }
  }, [tests, selectedTests, onTestsGenerated]);

  const canGenerate = response && response.status_code !== undefined;

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
          background: 'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(99, 102, 241, 0.1) 100%)',
          borderBottom: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <TestIcon sx={{ color: 'success.main' }} />
          <Typography variant="subtitle1" fontWeight={600}>
            AI Test Generator
          </Typography>
          <Chip 
            label="Auto-assertions" 
            size="small" 
            color="success" 
            variant="outlined"
            sx={{ ml: 'auto' }}
          />
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Automatically generate test assertions from your API response
        </Typography>
      </Box>

      <Box sx={{ p: 2 }}>
        {/* Generate button */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 2 }}>
          <Button
            variant="contained"
            color="success"
            startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <AIIcon />}
            onClick={handleGenerate}
            disabled={loading || !canGenerate}
          >
            Generate Tests
          </Button>
          {!canGenerate && (
            <Typography variant="caption" color="text.secondary">
              Execute a request first to generate tests
            </Typography>
          )}
        </Box>

        {/* Loading */}
        {loading && (
          <Box sx={{ mb: 2 }}>
            <LinearProgress color="success" />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: 'block' }}>
              AI is analyzing response and generating tests...
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

        {/* Generated tests */}
        {tests.length > 0 && (
          <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
              <Typography variant="subtitle2">
                Generated {tests.length} tests
              </Typography>
              <FormControlLabel
                control={
                  <Switch
                    size="small"
                    checked={selectedTests.size === tests.length}
                    onChange={handleSelectAll}
                  />
                }
                label={<Typography variant="caption">Select all</Typography>}
                sx={{ ml: 'auto' }}
              />
            </Box>

            <List dense sx={{ bgcolor: 'background.default', borderRadius: 1 }}>
              {tests.map((test, index) => (
                <Box key={index}>
                  <ListItem
                    sx={{
                      bgcolor: selectedTests.has(index) ? 'action.selected' : 'transparent',
                      borderRadius: 1,
                    }}
                  >
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <IconButton 
                        size="small" 
                        onClick={() => handleToggleTest(index)}
                        color={selectedTests.has(index) ? 'primary' : 'default'}
                      >
                        {selectedTests.has(index) ? <CheckIcon /> : <Box sx={{ width: 24, height: 24, border: '2px solid', borderColor: 'divider', borderRadius: 0.5 }} />}
                      </IconButton>
                    </ListItemIcon>
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <Tooltip title={test.type}>
                        <Box sx={{ color: TEST_TYPE_COLORS[test.type] || '#666' }}>
                          {TEST_TYPE_ICONS[test.type] || <TestIcon />}
                        </Box>
                      </Tooltip>
                    </ListItemIcon>
                    <ListItemText
                      primary={test.name}
                      secondary={test.description}
                      primaryTypographyProps={{ variant: 'body2', fontWeight: 500 }}
                      secondaryTypographyProps={{ variant: 'caption' }}
                    />
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      <Tooltip title="Copy test code">
                        <IconButton 
                          size="small" 
                          onClick={() => handleCopyCode(test, index)}
                        >
                          {copied === index ? <CheckIcon fontSize="small" color="success" /> : <CopyIcon fontSize="small" />}
                        </IconButton>
                      </Tooltip>
                      <IconButton
                        size="small"
                        onClick={() => setExpanded(expanded === index ? null : index)}
                      >
                        <ExpandMoreIcon 
                          fontSize="small"
                          sx={{ 
                            transform: expanded === index ? 'rotate(180deg)' : 'none',
                            transition: 'transform 0.2s',
                          }}
                        />
                      </IconButton>
                    </Box>
                  </ListItem>
                  
                  <Collapse in={expanded === index}>
                    <Box sx={{ px: 2, pb: 2, ml: 4 }}>
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 0.5 }}>
                        Test Code:
                      </Typography>
                      <Box
                        component="pre"
                        sx={{
                          bgcolor: '#1e1e1e',
                          color: '#d4d4d4',
                          p: 1.5,
                          borderRadius: 1,
                          fontSize: '0.75rem',
                          overflow: 'auto',
                          maxHeight: 150,
                          m: 0,
                        }}
                      >
                        {test.code}
                      </Box>
                      <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
                        <Chip label={`Type: ${test.type}`} size="small" variant="outlined" />
                        <Chip label={`Target: ${test.target || 'N/A'}`} size="small" variant="outlined" />
                        <Chip label={`Operator: ${test.operator}`} size="small" variant="outlined" />
                      </Box>
                    </Box>
                  </Collapse>
                  
                  {index < tests.length - 1 && <Divider />}
                </Box>
              ))}
            </List>

            {/* Actions */}
            <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
              <Button
                variant="contained"
                color="primary"
                disabled={selectedTests.size === 0}
                onClick={handleAddSelected}
              >
                Add {selectedTests.size} Test{selectedTests.size !== 1 ? 's' : ''} to Request
              </Button>
              <Button
                variant="outlined"
                onClick={() => {
                  const allCode = tests
                    .filter((_, i) => selectedTests.has(i))
                    .map(t => t.code)
                    .join('\n\n');
                  navigator.clipboard.writeText(allCode);
                }}
                disabled={selectedTests.size === 0}
                startIcon={<CopyIcon />}
              >
                Copy All Code
              </Button>
            </Box>
          </Box>
        )}

        {/* Empty state */}
        {tests.length === 0 && !loading && !error && (
          <Box sx={{ textAlign: 'center', py: 3, color: 'text.secondary' }}>
            <TestIcon sx={{ fontSize: 40, opacity: 0.5, mb: 1 }} />
            <Typography variant="body2">
              Click "Generate Tests" to create assertions from your response
            </Typography>
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default AITestGenerator;
