import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Button,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Chip,
  Alert,
  Paper,
  Stack,
  Collapse,
  Divider,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableRow,
  CircularProgress,
  Tooltip,
} from '@mui/material';
import {
  FiberManualRecord as RecordIcon,
  Stop as StopIcon,
  PlayArrow as PlayIcon,
  Delete as DeleteIcon,
  Add as AddIcon,
  ExpandMore as ExpandMoreIcon,
  Edit as EditIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Schedule as TimeIcon,
  Code as CodeIcon,
  DragHandle as DragIcon,
} from '@mui/icons-material';
import { mitmClient, Macro, MacroRunResult } from '../../api/client';

interface MacroRecorderPanelProps {
  proxyId: string;
  selectedTrafficIds?: string[];
  onMacroSelect?: (macro: Macro) => void;
}

const MacroRecorderPanel: React.FC<MacroRecorderPanelProps> = ({
  proxyId,
  selectedTrafficIds = [],
  onMacroSelect,
}) => {
  const [macros, setMacros] = useState<Macro[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [recording, setRecording] = useState(false);
  const [recordingMacroId, setRecordingMacroId] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [runDialogOpen, setRunDialogOpen] = useState(false);
  const [selectedMacro, setSelectedMacro] = useState<Macro | null>(null);
  const [runResult, setRunResult] = useState<MacroRunResult | null>(null);
  const [runningMacroId, setRunningMacroId] = useState<string | null>(null);
  const [newMacroName, setNewMacroName] = useState('');
  const [newMacroDesc, setNewMacroDesc] = useState('');
  const [runConfig, setRunConfig] = useState({
    baseUrl: '',
    variables: {} as Record<string, string>,
    timeoutPerStep: 30,
  });

  useEffect(() => {
    loadMacros();
    checkRecordingStatus();
  }, []);

  const loadMacros = async () => {
    try {
      setLoading(true);
      const data = await (mitmClient as any).listMacros();
      setMacros(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const checkRecordingStatus = async () => {
    try {
      const status = await (mitmClient as any).getMacroRecordingStatus();
      setRecording(status.recording);
      setRecordingMacroId(status.macro_id);
    } catch (err: any) {
      console.error('Failed to check recording status:', err);
    }
  };

  const handleStartRecording = async () => {
    if (!newMacroName.trim()) {
      setError('Please enter a macro name');
      return;
    }
    try {
      const result = await (mitmClient as any).startMacroRecording(newMacroName, newMacroDesc);
      setRecording(true);
      setRecordingMacroId(result.macro_id);
      setMacros([...macros, result.macro]);
      setCreateDialogOpen(false);
      setNewMacroName('');
      setNewMacroDesc('');
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleStopRecording = async () => {
    try {
      const result = await (mitmClient as any).stopMacroRecording();
      setRecording(false);
      setRecordingMacroId(null);
      // Update the macro in the list
      setMacros(macros.map((m) => (m.id === result.macro.id ? result.macro : m)));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleCreateFromTraffic = async () => {
    if (!newMacroName.trim()) {
      setError('Please enter a macro name');
      return;
    }
    if (selectedTrafficIds.length === 0) {
      setError('Please select traffic entries first');
      return;
    }
    try {
      const macro = await (mitmClient as any).createMacroFromTraffic(
        proxyId,
        selectedTrafficIds,
        newMacroName,
        newMacroDesc
      );
      setMacros([...macros, macro]);
      setCreateDialogOpen(false);
      setNewMacroName('');
      setNewMacroDesc('');
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeleteMacro = async (macroId: string) => {
    try {
      await (mitmClient as any).deleteMacro(macroId);
      setMacros(macros.filter((m) => m.id !== macroId));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleOpenRunDialog = (macro: Macro) => {
    setSelectedMacro(macro);
    setRunConfig({
      baseUrl: '',
      variables: { ...macro.variables },
      timeoutPerStep: 30,
    });
    setRunResult(null);
    setRunDialogOpen(true);
  };

  const handleRunMacro = async () => {
    if (!selectedMacro) return;
    if (!runConfig.baseUrl.trim()) {
      setError('Please enter a base URL');
      return;
    }
    try {
      setRunningMacroId(selectedMacro.id);
      const result = await (mitmClient as any).runMacro(
        selectedMacro.id,
        runConfig.baseUrl,
        runConfig.variables,
        runConfig.timeoutPerStep
      );
      setRunResult(result);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRunningMacroId(null);
    }
  };

  const getMethodColor = (method: string) => {
    const colors: Record<string, string> = {
      GET: '#4caf50',
      POST: '#2196f3',
      PUT: '#ff9800',
      DELETE: '#f44336',
      PATCH: '#9c27b0',
    };
    return colors[method] || '#757575';
  };

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Paper sx={{ p: 2 }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            <CodeIcon color="primary" />
            <Typography variant="h6">Macro Recorder</Typography>
          </Stack>
          
          {recording ? (
            <Button
              variant="contained"
              color="error"
              startIcon={<StopIcon />}
              onClick={handleStopRecording}
            >
              Stop Recording
            </Button>
          ) : (
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={() => setCreateDialogOpen(true)}
            >
              New Macro
            </Button>
          )}
        </Stack>

        {recording && (
          <Alert
            severity="info"
            icon={<RecordIcon sx={{ animation: 'pulse 1.5s infinite', color: '#f44336' }} />}
            sx={{ mb: 2 }}
          >
            Recording in progress... Requests are being captured automatically.
          </Alert>
        )}

        {loading ? (
          <LinearProgress />
        ) : macros.length === 0 ? (
          <Typography color="text.secondary" align="center" sx={{ py: 4 }}>
            No macros yet. Create one by recording traffic or selecting existing entries.
          </Typography>
        ) : (
          <List>
            {macros.map((macro) => (
              <Accordion key={macro.id} sx={{ mb: 1 }}>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Stack direction="row" alignItems="center" spacing={2} sx={{ width: '100%', pr: 2 }}>
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="subtitle1">{macro.name}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {macro.steps.length} steps | Last run:{' '}
                        {macro.last_run_at
                          ? new Date(macro.last_run_at).toLocaleString()
                          : 'Never'}
                      </Typography>
                    </Box>
                    <Chip
                      size="small"
                      label={`${macro.run_count} runs`}
                      variant="outlined"
                    />
                    {macro.tags.map((tag) => (
                      <Chip key={tag} size="small" label={tag} />
                    ))}
                  </Stack>
                </AccordionSummary>
                <AccordionDetails>
                  {macro.description && (
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      {macro.description}
                    </Typography>
                  )}

                  <Typography variant="subtitle2" gutterBottom>
                    Steps:
                  </Typography>
                  <List dense>
                    {macro.steps.map((step, index) => (
                      <ListItem key={step.id} sx={{ pl: 0 }}>
                        <Typography
                          component="span"
                          sx={{
                            mr: 1,
                            px: 1,
                            py: 0.25,
                            borderRadius: 1,
                            bgcolor: getMethodColor(step.method),
                            color: 'white',
                            fontSize: '0.75rem',
                            fontWeight: 'bold',
                          }}
                        >
                          {step.method}
                        </Typography>
                        <ListItemText
                          primary={step.path}
                          secondary={
                            step.extract_variables &&
                            Object.keys(step.extract_variables).length > 0
                              ? `Extracts: ${Object.keys(step.extract_variables).join(', ')}`
                              : undefined
                          }
                        />
                        {step.delay_ms > 0 && (
                          <Tooltip title="Delay before this step">
                            <Chip
                              size="small"
                              icon={<TimeIcon />}
                              label={`${step.delay_ms}ms`}
                              variant="outlined"
                            />
                          </Tooltip>
                        )}
                      </ListItem>
                    ))}
                  </List>

                  {Object.keys(macro.variables).length > 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        Variables:
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {Object.entries(macro.variables).map(([key, value]) => (
                          <Chip
                            key={key}
                            size="small"
                            label={`${key}: ${value || '(empty)'}`}
                            variant="outlined"
                          />
                        ))}
                      </Stack>
                    </Box>
                  )}

                  <Divider sx={{ my: 2 }} />

                  <Stack direction="row" spacing={1} justifyContent="flex-end">
                    <Button
                      size="small"
                      startIcon={<PlayIcon />}
                      variant="contained"
                      onClick={() => handleOpenRunDialog(macro)}
                      disabled={runningMacroId === macro.id}
                    >
                      {runningMacroId === macro.id ? (
                        <CircularProgress size={20} />
                      ) : (
                        'Run'
                      )}
                    </Button>
                    <Button
                      size="small"
                      startIcon={<DeleteIcon />}
                      color="error"
                      onClick={() => handleDeleteMacro(macro.id)}
                    >
                      Delete
                    </Button>
                  </Stack>
                </AccordionDetails>
              </Accordion>
            ))}
          </List>
        )}
      </Paper>

      {/* Create Macro Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create New Macro</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 2 }}>
            <TextField
              label="Macro Name"
              value={newMacroName}
              onChange={(e) => setNewMacroName(e.target.value)}
              fullWidth
              required
            />
            <TextField
              label="Description"
              value={newMacroDesc}
              onChange={(e) => setNewMacroDesc(e.target.value)}
              fullWidth
              multiline
              rows={2}
            />
            {selectedTrafficIds.length > 0 && (
              <Alert severity="info">
                {selectedTrafficIds.length} traffic entries selected. You can create a macro from
                these entries.
              </Alert>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          {selectedTrafficIds.length > 0 && (
            <Button onClick={handleCreateFromTraffic} variant="outlined">
              Create from Selection
            </Button>
          )}
          <Button onClick={handleStartRecording} variant="contained" color="error">
            <RecordIcon sx={{ mr: 1 }} />
            Start Recording
          </Button>
        </DialogActions>
      </Dialog>

      {/* Run Macro Dialog */}
      <Dialog
        open={runDialogOpen}
        onClose={() => setRunDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Run Macro: {selectedMacro?.name}</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 2 }}>
            <TextField
              label="Base URL"
              value={runConfig.baseUrl}
              onChange={(e) => setRunConfig({ ...runConfig, baseUrl: e.target.value })}
              placeholder="https://api.example.com"
              fullWidth
              required
              helperText="The base URL to prepend to all request paths"
            />
            
            <TextField
              label="Timeout per Step (seconds)"
              type="number"
              value={runConfig.timeoutPerStep}
              onChange={(e) =>
                setRunConfig({ ...runConfig, timeoutPerStep: parseInt(e.target.value) || 30 })
              }
              fullWidth
            />

            {selectedMacro && Object.keys(selectedMacro.variables).length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Variables:
                </Typography>
                <Stack spacing={2}>
                  {Object.keys(selectedMacro.variables).map((varName) => (
                    <TextField
                      key={varName}
                      label={varName}
                      value={runConfig.variables[varName] || ''}
                      onChange={(e) =>
                        setRunConfig({
                          ...runConfig,
                          variables: { ...runConfig.variables, [varName]: e.target.value },
                        })
                      }
                      size="small"
                      fullWidth
                    />
                  ))}
                </Stack>
              </Box>
            )}

            {runResult && (
              <Box>
                <Divider sx={{ my: 2 }} />
                <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 2 }}>
                  {runResult.success ? (
                    <SuccessIcon color="success" />
                  ) : (
                    <ErrorIcon color="error" />
                  )}
                  <Typography variant="h6">
                    {runResult.success ? 'Macro Completed' : 'Macro Failed'}
                  </Typography>
                  <Chip
                    size="small"
                    label={`${runResult.steps_completed}/${runResult.total_steps} steps`}
                  />
                  <Chip
                    size="small"
                    label={`${runResult.total_time_ms}ms`}
                    icon={<TimeIcon />}
                  />
                </Stack>

                <Typography variant="subtitle2" gutterBottom>
                  Step Results:
                </Typography>
                <Table size="small">
                  <TableBody>
                    {runResult.step_results.map((stepResult, idx) => (
                      <TableRow key={stepResult.step_id}>
                        <TableCell>
                          {stepResult.success ? (
                            <SuccessIcon color="success" fontSize="small" />
                          ) : (
                            <ErrorIcon color="error" fontSize="small" />
                          )}
                        </TableCell>
                        <TableCell>Step {idx + 1}</TableCell>
                        <TableCell>
                          {stepResult.status_code && (
                            <Chip
                              size="small"
                              label={stepResult.status_code}
                              color={stepResult.status_code < 400 ? 'success' : 'error'}
                            />
                          )}
                        </TableCell>
                        <TableCell>{stepResult.time_ms}ms</TableCell>
                        <TableCell>
                          {stepResult.error && (
                            <Typography variant="caption" color="error">
                              {stepResult.error}
                            </Typography>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>

                {Object.keys(runResult.final_variables).length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Final Variables:
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {Object.entries(runResult.final_variables).map(([key, value]) => (
                        <Chip
                          key={key}
                          size="small"
                          label={`${key}: ${value}`}
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Box>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRunDialogOpen(false)}>Close</Button>
          <Button
            onClick={handleRunMacro}
            variant="contained"
            disabled={!runConfig.baseUrl || runningMacroId !== null}
            startIcon={runningMacroId ? <CircularProgress size={20} /> : <PlayIcon />}
          >
            {runningMacroId ? 'Running...' : 'Run Macro'}
          </Button>
        </DialogActions>
      </Dialog>

      <style>
        {`
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.3; }
          }
        `}
      </style>
    </Box>
  );
};

export default MacroRecorderPanel;
