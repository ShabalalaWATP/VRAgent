import React, { useState, useCallback, useEffect } from 'react';
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
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  AutoAwesome as AIIcon,
  VpnKey as KeyIcon,
  ContentCopy as CopyIcon,
  Check as CheckIcon,
  Add as AddIcon,
  Cloud as CloudIcon,
  Link as LinkIcon,
  Numbers as NumbersIcon,
  Token as TokenIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import { apiCollections, AISuggestedVariable, AISuggestedVariables } from '../api/client';

interface SmartVariableSuggesterProps {
  responseBody: string;
  requestContext?: Record<string, any>;
  onVariableAdd?: (variable: {
    name: string;
    value: any;
    scope: string;
    jsonPath: string;
  }) => void;
  compact?: boolean;
}

const VARIABLE_TYPE_ICONS: Record<string, React.ReactNode> = {
  id: <KeyIcon />,
  token: <TokenIcon />,
  url: <LinkIcon />,
  number: <NumbersIcon />,
  default: <CloudIcon />,
};

const SCOPE_COLORS: Record<string, string> = {
  environment: 'primary',
  collection: 'secondary',
  global: 'warning',
};

export const SmartVariableSuggester: React.FC<SmartVariableSuggesterProps> = ({
  responseBody,
  requestContext,
  onVariableAdd,
  compact = false,
}) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [variables, setVariables] = useState<AISuggestedVariable[]>([]);
  const [copied, setCopied] = useState<string | null>(null);
  const [editDialog, setEditDialog] = useState<{
    open: boolean;
    variable: AISuggestedVariable | null;
    name: string;
    scope: string;
  }>({ open: false, variable: null, name: '', scope: 'environment' });

  const handleAnalyze = useCallback(async () => {
    if (!responseBody || responseBody.trim() === '') return;

    setLoading(true);
    setError(null);
    setVariables([]);

    try {
      const result = await apiCollections.aiSuggestVariables({
        response_body: responseBody,
        request_context: requestContext,
      });

      setVariables(result.variables);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze response');
    } finally {
      setLoading(false);
    }
  }, [responseBody, requestContext]);

  // Auto-analyze when response body changes
  useEffect(() => {
    if (responseBody && responseBody.trim() !== '') {
      const timer = setTimeout(() => {
        handleAnalyze();
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [responseBody]);

  const handleCopyPath = useCallback((jsonPath: string) => {
    navigator.clipboard.writeText(jsonPath);
    setCopied(jsonPath);
    setTimeout(() => setCopied(null), 2000);
  }, []);

  const handleOpenEditDialog = useCallback((variable: AISuggestedVariable) => {
    setEditDialog({
      open: true,
      variable,
      name: variable.name,
      scope: variable.scope,
    });
  }, []);

  const handleCloseEditDialog = useCallback(() => {
    setEditDialog({ open: false, variable: null, name: '', scope: 'environment' });
  }, []);

  const handleAddVariable = useCallback(() => {
    if (editDialog.variable && onVariableAdd) {
      onVariableAdd({
        name: editDialog.name,
        value: editDialog.variable.sample_value,
        scope: editDialog.scope,
        jsonPath: editDialog.variable.json_path,
      });
      handleCloseEditDialog();
    }
  }, [editDialog, onVariableAdd, handleCloseEditDialog]);

  const handleQuickAdd = useCallback((variable: AISuggestedVariable) => {
    if (onVariableAdd) {
      onVariableAdd({
        name: variable.name,
        value: variable.sample_value,
        scope: variable.scope,
        jsonPath: variable.json_path,
      });
    }
  }, [onVariableAdd]);

  const getVariableIcon = (variable: AISuggestedVariable) => {
    const name = variable.name.toLowerCase();
    if (name.includes('id')) return VARIABLE_TYPE_ICONS.id;
    if (name.includes('token') || name.includes('jwt') || name.includes('bearer')) return VARIABLE_TYPE_ICONS.token;
    if (name.includes('url') || name.includes('link') || name.includes('href')) return VARIABLE_TYPE_ICONS.url;
    if (typeof variable.sample_value === 'number') return VARIABLE_TYPE_ICONS.number;
    return VARIABLE_TYPE_ICONS.default;
  };

  const formatValue = (value: any): string => {
    if (value === null) return 'null';
    if (value === undefined) return 'undefined';
    if (typeof value === 'string') {
      return value.length > 50 ? value.substring(0, 50) + '...' : value;
    }
    if (typeof value === 'object') {
      return JSON.stringify(value).substring(0, 50) + '...';
    }
    return String(value);
  };

  const canAnalyze = responseBody && responseBody.trim() !== '';

  if (compact) {
    return (
      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', flexWrap: 'wrap' }}>
        {variables.length > 0 && (
          <>
            <Typography variant="caption" color="text.secondary">
              Suggested:
            </Typography>
            {variables.slice(0, 3).map((v, i) => (
              <Chip
                key={i}
                label={`{{${v.name}}}`}
                size="small"
                icon={<AddIcon />}
                onClick={() => handleQuickAdd(v)}
                variant="outlined"
                color="primary"
                sx={{ cursor: 'pointer' }}
              />
            ))}
            {variables.length > 3 && (
              <Chip label={`+${variables.length - 3} more`} size="small" variant="outlined" />
            )}
          </>
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
          background: 'linear-gradient(135deg, rgba(251, 191, 36, 0.1) 0%, rgba(245, 158, 11, 0.1) 100%)',
          borderBottom: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <KeyIcon sx={{ color: 'warning.main' }} />
          <Typography variant="subtitle1" fontWeight={600}>
            Smart Variable Detector
          </Typography>
          <Chip 
            label="AI-Powered" 
            size="small" 
            color="warning" 
            variant="outlined"
            sx={{ ml: 'auto' }}
          />
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          AI detects useful values to extract as variables for subsequent requests
        </Typography>
      </Box>

      <Box sx={{ p: 2 }}>
        {/* Analyze button */}
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mb: 2 }}>
          <Button
            variant="contained"
            color="warning"
            startIcon={loading ? <CircularProgress size={16} color="inherit" /> : <AIIcon />}
            onClick={handleAnalyze}
            disabled={loading || !canAnalyze}
          >
            Analyze Response
          </Button>
          {!canAnalyze && (
            <Typography variant="caption" color="text.secondary">
              Execute a request to analyze the response
            </Typography>
          )}
        </Box>

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

        {/* Variables list */}
        {variables.length > 0 && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              {variables.length} Variable{variables.length !== 1 ? 's' : ''} Detected
            </Typography>

            <List dense sx={{ bgcolor: 'background.default', borderRadius: 1 }}>
              {variables.map((variable, index) => (
                <Box key={index}>
                  <ListItem
                    secondaryAction={
                      <Box sx={{ display: 'flex', gap: 0.5 }}>
                        <Tooltip title="Copy JSON path">
                          <IconButton 
                            size="small" 
                            onClick={() => handleCopyPath(variable.json_path)}
                          >
                            {copied === variable.json_path ? (
                              <CheckIcon fontSize="small" color="success" />
                            ) : (
                              <CopyIcon fontSize="small" />
                            )}
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Add variable">
                          <IconButton 
                            size="small" 
                            color="primary"
                            onClick={() => handleOpenEditDialog(variable)}
                          >
                            <AddIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    }
                  >
                    <ListItemIcon sx={{ minWidth: 36 }}>
                      <Box sx={{ color: 'warning.main' }}>
                        {getVariableIcon(variable)}
                      </Box>
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography 
                            variant="body2" 
                            fontFamily="monospace"
                            fontWeight={600}
                            color="primary"
                          >
                            {`{{${variable.name}}}`}
                          </Typography>
                          <Chip 
                            label={variable.scope} 
                            size="small" 
                            color={SCOPE_COLORS[variable.scope] as any || 'default'}
                            variant="outlined"
                          />
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 0.5 }}>
                          <Typography variant="caption" color="text.secondary" display="block">
                            {variable.description}
                          </Typography>
                          <Box sx={{ display: 'flex', gap: 1, alignItems: 'center', mt: 0.5 }}>
                            <Typography variant="caption" fontFamily="monospace" color="text.secondary">
                              {variable.json_path}
                            </Typography>
                            <Typography variant="caption" fontFamily="monospace" sx={{ 
                              bgcolor: 'action.hover', 
                              px: 0.5, 
                              borderRadius: 0.5,
                              maxWidth: 200,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}>
                              = {formatValue(variable.sample_value)}
                            </Typography>
                          </Box>
                        </Box>
                      }
                    />
                  </ListItem>
                  {index < variables.length - 1 && <Divider />}
                </Box>
              ))}
            </List>

            <Alert severity="info" sx={{ mt: 2 }}>
              <Typography variant="caption">
                Use <code>{`{{variableName}}`}</code> syntax in URLs, headers, or body to reference these variables.
              </Typography>
            </Alert>
          </Box>
        )}

        {/* Empty state */}
        {variables.length === 0 && !loading && !error && (
          <Box sx={{ textAlign: 'center', py: 3, color: 'text.secondary' }}>
            <KeyIcon sx={{ fontSize: 40, opacity: 0.5, mb: 1 }} />
            <Typography variant="body2">
              {canAnalyze 
                ? 'Click "Analyze Response" to detect variables'
                : 'Execute a request first to detect variables'}
            </Typography>
          </Box>
        )}
      </Box>

      {/* Edit Dialog */}
      <Dialog open={editDialog.open} onClose={handleCloseEditDialog} maxWidth="xs" fullWidth>
        <DialogTitle>Add Variable</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <TextField
              label="Variable Name"
              value={editDialog.name}
              onChange={(e) => setEditDialog(prev => ({ ...prev, name: e.target.value }))}
              fullWidth
              size="small"
              helperText={`Will be referenced as {{${editDialog.name}}}`}
            />
            <FormControl fullWidth size="small">
              <InputLabel>Scope</InputLabel>
              <Select
                value={editDialog.scope}
                label="Scope"
                onChange={(e) => setEditDialog(prev => ({ ...prev, scope: e.target.value }))}
              >
                <MenuItem value="environment">Environment</MenuItem>
                <MenuItem value="collection">Collection</MenuItem>
                <MenuItem value="global">Global</MenuItem>
              </Select>
            </FormControl>
            {editDialog.variable && (
              <Box>
                <Typography variant="caption" color="text.secondary">
                  JSON Path:
                </Typography>
                <Typography variant="body2" fontFamily="monospace">
                  {editDialog.variable.json_path}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  Current Value:
                </Typography>
                <Typography 
                  variant="body2" 
                  fontFamily="monospace"
                  sx={{ 
                    bgcolor: 'action.hover', 
                    p: 1, 
                    borderRadius: 1,
                    wordBreak: 'break-all',
                  }}
                >
                  {formatValue(editDialog.variable.sample_value)}
                </Typography>
              </Box>
            )}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseEditDialog}>Cancel</Button>
          <Button 
            onClick={handleAddVariable} 
            variant="contained" 
            disabled={!editDialog.name.trim()}
          >
            Add Variable
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  );
};

export default SmartVariableSuggester;
