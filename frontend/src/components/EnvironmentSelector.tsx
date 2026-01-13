import React, { useState, useEffect, useCallback } from "react";
import {
  Box,
  Typography,
  Button,
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  CircularProgress,
  Alert,
  Paper,
  Tabs,
  Tab,
  Switch,
  FormControlLabel,
} from "@mui/material";
import {
  ExpandMore as ExpandMoreIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ContentCopy as DuplicateIcon,
  Check as CheckIcon,
  Public as GlobalIcon,
  Settings as SettingsIcon,
  Visibility as VisibilityIcon,
  VisibilityOff as VisibilityOffIcon,
  CloudQueue as EnvironmentIcon,
} from "@mui/icons-material";
import {
  apiCollections,
  APIEnvironment,
  APIGlobalVariable,
} from "../api/client";

// Tab panel component
function TabPanel({ children, value, index, ...other }: any) {
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

interface EnvironmentVariable {
  key: string;
  value: string;
  type?: string;
  enabled?: boolean;
}

interface EnvironmentSelectorProps {
  onEnvironmentChange?: (environment: APIEnvironment | null) => void;
  compact?: boolean;
}

export default function EnvironmentSelector({
  onEnvironmentChange,
  compact = false,
}: EnvironmentSelectorProps) {
  // State
  const [environments, setEnvironments] = useState<APIEnvironment[]>([]);
  const [activeEnvironment, setActiveEnvironment] = useState<APIEnvironment | null>(null);
  const [globalVariables, setGlobalVariables] = useState<APIGlobalVariable[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Menu state
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const menuOpen = Boolean(anchorEl);

  // Dialog states
  const [manageOpen, setManageOpen] = useState(false);
  const [manageTab, setManageTab] = useState(0);
  const [editEnv, setEditEnv] = useState<APIEnvironment | null>(null);
  const [editEnvOpen, setEditEnvOpen] = useState(false);
  const [newEnvOpen, setNewEnvOpen] = useState(false);
  const [newEnvName, setNewEnvName] = useState("");
  const [newEnvColor, setNewEnvColor] = useState("#4caf50");

  // Variable editing
  const [editVars, setEditVars] = useState<EnvironmentVariable[]>([]);
  const [showSecrets, setShowSecrets] = useState(false);

  // Global variable editing
  const [newGlobalKey, setNewGlobalKey] = useState("");
  const [newGlobalValue, setNewGlobalValue] = useState("");
  const [newGlobalSecret, setNewGlobalSecret] = useState(false);
  const [editingGlobal, setEditingGlobal] = useState<APIGlobalVariable | null>(null);

  // Load data
  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [envResult, activeResult, globalsResult] = await Promise.all([
        apiCollections.listEnvironments(),
        apiCollections.getActiveEnvironment(),
        apiCollections.listGlobalVariables(),
      ]);
      setEnvironments(envResult.environments);
      setActiveEnvironment(activeResult.environment);
      setGlobalVariables(globalsResult.variables);
      
      if (onEnvironmentChange) {
        onEnvironmentChange(activeResult.environment);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load environments");
    } finally {
      setLoading(false);
    }
  }, [onEnvironmentChange]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle menu
  const handleMenuClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  // Select environment
  const handleSelectEnvironment = async (env: APIEnvironment | null) => {
    handleMenuClose();
    try {
      if (env) {
        await apiCollections.activateEnvironment(env.id!);
        setActiveEnvironment(env);
      } else {
        await apiCollections.deactivateEnvironments();
        setActiveEnvironment(null);
      }
      if (onEnvironmentChange) {
        onEnvironmentChange(env);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Create environment
  const handleCreateEnvironment = async () => {
    if (!newEnvName.trim()) return;
    try {
      await apiCollections.createEnvironment({
        name: newEnvName.trim(),
        color: newEnvColor,
        variables: [],
      });
      setNewEnvOpen(false);
      setNewEnvName("");
      setNewEnvColor("#4caf50");
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Edit environment
  const handleEditEnvironment = (env: APIEnvironment) => {
    setEditEnv(env);
    setEditVars(env.variables?.map(v => ({ ...v, enabled: v.enabled ?? true })) || []);
    setEditEnvOpen(true);
  };

  const handleSaveEnvironment = async () => {
    if (!editEnv) return;
    try {
      await apiCollections.updateEnvironment(editEnv.id!, {
        name: editEnv.name,
        description: editEnv.description,
        variables: editVars,
        color: editEnv.color,
      });
      setEditEnvOpen(false);
      setEditEnv(null);
      setEditVars([]);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Delete environment
  const handleDeleteEnvironment = async (env: APIEnvironment) => {
    if (!confirm(`Delete environment "${env.name}"?`)) return;
    try {
      await apiCollections.deleteEnvironment(env.id!);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Duplicate environment
  const handleDuplicateEnvironment = async (env: APIEnvironment) => {
    try {
      await apiCollections.duplicateEnvironment(env.id!);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Variable management
  const addVariable = () => {
    setEditVars([...editVars, { key: "", value: "", type: "default", enabled: true }]);
  };

  const updateVariable = (index: number, field: string, value: any) => {
    const updated = [...editVars];
    (updated[index] as any)[field] = value;
    setEditVars(updated);
  };

  const removeVariable = (index: number) => {
    setEditVars(editVars.filter((_, i) => i !== index));
  };

  // Global variable management
  const handleCreateGlobal = async () => {
    if (!newGlobalKey.trim()) return;
    try {
      await apiCollections.createGlobalVariable({
        key: newGlobalKey.trim(),
        value: newGlobalValue,
        is_secret: newGlobalSecret,
      });
      setNewGlobalKey("");
      setNewGlobalValue("");
      setNewGlobalSecret(false);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleUpdateGlobal = async () => {
    if (!editingGlobal) return;
    try {
      await apiCollections.updateGlobalVariable(editingGlobal.id!, {
        key: editingGlobal.key,
        value: editingGlobal.value,
        is_secret: editingGlobal.is_secret,
      });
      setEditingGlobal(null);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeleteGlobal = async (variable: APIGlobalVariable) => {
    if (!confirm(`Delete global variable "${variable.key}"?`)) return;
    try {
      await apiCollections.deleteGlobalVariable(variable.id!);
      loadData();
    } catch (err: any) {
      setError(err.message);
    }
  };

  // Color presets
  const colorPresets = [
    "#4caf50", // Green - Production
    "#ff9800", // Orange - Staging
    "#2196f3", // Blue - Development
    "#9c27b0", // Purple - QA
    "#f44336", // Red - Local
    "#607d8b", // Gray - Test
  ];

  return (
    <>
      {/* Environment Selector Button */}
      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <Button
          variant="outlined"
          size={compact ? "small" : "medium"}
          onClick={handleMenuClick}
          endIcon={<ExpandMoreIcon />}
          startIcon={
            activeEnvironment ? (
              <Box
                sx={{
                  width: 12,
                  height: 12,
                  borderRadius: "50%",
                  bgcolor: activeEnvironment.color || "#4caf50",
                }}
              />
            ) : (
              <EnvironmentIcon fontSize="small" />
            )
          }
          sx={{
            minWidth: compact ? 120 : 150,
            justifyContent: "space-between",
            borderColor: activeEnvironment?.color || undefined,
          }}
        >
          {activeEnvironment?.name || "No Environment"}
        </Button>

        <Tooltip title="Manage Environments & Variables">
          <IconButton size="small" onClick={() => setManageOpen(true)}>
            <SettingsIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>

      {/* Environment Menu */}
      <Menu
        anchorEl={anchorEl}
        open={menuOpen}
        onClose={handleMenuClose}
        PaperProps={{ sx: { minWidth: 200 } }}
      >
        <MenuItem onClick={() => handleSelectEnvironment(null)}>
          <ListItemText primary="No Environment" />
          {!activeEnvironment && <CheckIcon fontSize="small" color="primary" />}
        </MenuItem>
        <Divider />
        {environments.map((env) => (
          <MenuItem key={env.id} onClick={() => handleSelectEnvironment(env)}>
            <ListItemIcon>
              <Box
                sx={{
                  width: 12,
                  height: 12,
                  borderRadius: "50%",
                  bgcolor: env.color || "#4caf50",
                }}
              />
            </ListItemIcon>
            <ListItemText primary={env.name} />
            {activeEnvironment?.id === env.id && <CheckIcon fontSize="small" color="primary" />}
          </MenuItem>
        ))}
        <Divider />
        <MenuItem onClick={() => { handleMenuClose(); setNewEnvOpen(true); }}>
          <ListItemIcon><AddIcon fontSize="small" /></ListItemIcon>
          <ListItemText primary="New Environment" />
        </MenuItem>
        <MenuItem onClick={() => { handleMenuClose(); setManageOpen(true); }}>
          <ListItemIcon><SettingsIcon fontSize="small" /></ListItemIcon>
          <ListItemText primary="Manage..." />
        </MenuItem>
      </Menu>

      {/* Manage Dialog */}
      <Dialog open={manageOpen} onClose={() => setManageOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Manage Environments & Variables</DialogTitle>
        <DialogContent>
          {error && (
            <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Tabs value={manageTab} onChange={(_, v) => setManageTab(v)} sx={{ mb: 2 }}>
            <Tab icon={<EnvironmentIcon />} label="Environments" iconPosition="start" />
            <Tab icon={<GlobalIcon />} label="Global Variables" iconPosition="start" />
          </Tabs>

          {/* Environments Tab */}
          <TabPanel value={manageTab} index={0}>
            <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
              <Button startIcon={<AddIcon />} variant="contained" onClick={() => setNewEnvOpen(true)}>
                New Environment
              </Button>
            </Box>

            {loading ? (
              <Box sx={{ display: "flex", justifyContent: "center", p: 3 }}>
                <CircularProgress />
              </Box>
            ) : environments.length === 0 ? (
              <Typography color="text.secondary" sx={{ textAlign: "center", py: 3 }}>
                No environments yet. Create one to get started.
              </Typography>
            ) : (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Variables</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {environments.map((env) => (
                      <TableRow key={env.id} hover>
                        <TableCell>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Box
                              sx={{
                                width: 16,
                                height: 16,
                                borderRadius: "50%",
                                bgcolor: env.color || "#4caf50",
                              }}
                            />
                            <Typography variant="body2" fontWeight={env.is_active ? "bold" : "normal"}>
                              {env.name}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Chip label={env.variables?.length || 0} size="small" />
                        </TableCell>
                        <TableCell>
                          {env.is_active && <Chip label="Active" size="small" color="success" />}
                        </TableCell>
                        <TableCell align="right">
                          <IconButton size="small" onClick={() => handleEditEnvironment(env)}>
                            <EditIcon fontSize="small" />
                          </IconButton>
                          <IconButton size="small" onClick={() => handleDuplicateEnvironment(env)}>
                            <DuplicateIcon fontSize="small" />
                          </IconButton>
                          <IconButton size="small" color="error" onClick={() => handleDeleteEnvironment(env)}>
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </TabPanel>

          {/* Global Variables Tab */}
          <TabPanel value={manageTab} index={1}>
            <Box sx={{ mb: 3, p: 2, bgcolor: "background.default", borderRadius: 1 }}>
              <Typography variant="subtitle2" gutterBottom>Add Global Variable</Typography>
              <Box sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                <TextField
                  size="small"
                  label="Key"
                  value={newGlobalKey}
                  onChange={(e) => setNewGlobalKey(e.target.value)}
                  sx={{ flex: 1 }}
                />
                <TextField
                  size="small"
                  label="Value"
                  type={newGlobalSecret ? "password" : "text"}
                  value={newGlobalValue}
                  onChange={(e) => setNewGlobalValue(e.target.value)}
                  sx={{ flex: 2 }}
                />
                <FormControlLabel
                  control={
                    <Switch
                      size="small"
                      checked={newGlobalSecret}
                      onChange={(e) => setNewGlobalSecret(e.target.checked)}
                    />
                  }
                  label="Secret"
                />
                <Button variant="contained" onClick={handleCreateGlobal} disabled={!newGlobalKey.trim()}>
                  Add
                </Button>
              </Box>
            </Box>

            {globalVariables.length === 0 ? (
              <Typography color="text.secondary" sx={{ textAlign: "center", py: 3 }}>
                No global variables. These persist across all environments.
              </Typography>
            ) : (
              <TableContainer component={Paper} variant="outlined">
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Key</TableCell>
                      <TableCell>Value</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell align="right">Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {globalVariables.map((v) => (
                      <TableRow key={v.id} hover>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {v.key}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {v.is_secret ? (showSecrets ? v.value : "••••••••") : v.value}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {v.is_secret && <Chip label="Secret" size="small" color="warning" />}
                        </TableCell>
                        <TableCell align="right">
                          <IconButton
                            size="small"
                            onClick={() => setEditingGlobal(v)}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => handleDeleteGlobal(v)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}

            {globalVariables.some((v) => v.is_secret) && (
              <Box sx={{ mt: 2 }}>
                <Button
                  size="small"
                  startIcon={showSecrets ? <VisibilityOffIcon /> : <VisibilityIcon />}
                  onClick={() => setShowSecrets(!showSecrets)}
                >
                  {showSecrets ? "Hide Secrets" : "Show Secrets"}
                </Button>
              </Box>
            )}
          </TabPanel>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setManageOpen(false)}>Close</Button>
        </DialogActions>
      </Dialog>

      {/* New Environment Dialog */}
      <Dialog open={newEnvOpen} onClose={() => setNewEnvOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>New Environment</DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Environment Name"
            value={newEnvName}
            onChange={(e) => setNewEnvName(e.target.value)}
            sx={{ mt: 1, mb: 2 }}
            placeholder="e.g., Development, Staging, Production"
          />
          <Typography variant="subtitle2" gutterBottom>Color</Typography>
          <Box sx={{ display: "flex", gap: 1 }}>
            {colorPresets.map((color) => (
              <Box
                key={color}
                onClick={() => setNewEnvColor(color)}
                sx={{
                  width: 32,
                  height: 32,
                  borderRadius: "50%",
                  bgcolor: color,
                  cursor: "pointer",
                  border: newEnvColor === color ? "3px solid white" : "none",
                  boxShadow: newEnvColor === color ? `0 0 0 2px ${color}` : "none",
                }}
              />
            ))}
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNewEnvOpen(false)}>Cancel</Button>
          <Button onClick={handleCreateEnvironment} variant="contained" disabled={!newEnvName.trim()}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Environment Dialog */}
      <Dialog open={editEnvOpen} onClose={() => setEditEnvOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>Edit Environment: {editEnv?.name}</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", gap: 2, mb: 3 }}>
            <TextField
              label="Name"
              value={editEnv?.name || ""}
              onChange={(e) => setEditEnv(editEnv ? { ...editEnv, name: e.target.value } : null)}
              sx={{ flex: 1 }}
            />
            <Box>
              <Typography variant="caption" color="text.secondary">Color</Typography>
              <Box sx={{ display: "flex", gap: 0.5, mt: 0.5 }}>
                {colorPresets.map((color) => (
                  <Box
                    key={color}
                    onClick={() => setEditEnv(editEnv ? { ...editEnv, color } : null)}
                    sx={{
                      width: 24,
                      height: 24,
                      borderRadius: "50%",
                      bgcolor: color,
                      cursor: "pointer",
                      border: editEnv?.color === color ? "2px solid white" : "none",
                      boxShadow: editEnv?.color === color ? `0 0 0 1px ${color}` : "none",
                    }}
                  />
                ))}
              </Box>
            </Box>
          </Box>

          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
            Variables
            <Button size="small" startIcon={<AddIcon />} onClick={addVariable}>
              Add Variable
            </Button>
          </Typography>

          <TableContainer component={Paper} variant="outlined" sx={{ maxHeight: 300 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Key</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell width={80}>Enabled</TableCell>
                  <TableCell width={60}></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {editVars.map((v, i) => (
                  <TableRow key={i}>
                    <TableCell>
                      <TextField
                        size="small"
                        fullWidth
                        value={v.key}
                        onChange={(e) => updateVariable(i, "key", e.target.value)}
                        placeholder="variable_name"
                      />
                    </TableCell>
                    <TableCell>
                      <TextField
                        size="small"
                        fullWidth
                        type={v.type === "secret" ? "password" : "text"}
                        value={v.value}
                        onChange={(e) => updateVariable(i, "value", e.target.value)}
                        placeholder="value"
                      />
                    </TableCell>
                    <TableCell>
                      <Switch
                        size="small"
                        checked={v.enabled !== false}
                        onChange={(e) => updateVariable(i, "enabled", e.target.checked)}
                      />
                    </TableCell>
                    <TableCell>
                      <IconButton size="small" color="error" onClick={() => removeVariable(i)}>
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </TableCell>
                  </TableRow>
                ))}
                {editVars.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4}>
                      <Typography variant="body2" color="text.secondary" sx={{ textAlign: "center", py: 2 }}>
                        No variables. Click "Add Variable" to create one.
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>

          <Alert severity="info" sx={{ mt: 2 }}>
            Use <code>{"{{variable_name}}"}</code> in your URLs, headers, or body to substitute values.
          </Alert>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditEnvOpen(false)}>Cancel</Button>
          <Button onClick={handleSaveEnvironment} variant="contained">
            Save Changes
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit Global Variable Dialog */}
      <Dialog open={!!editingGlobal} onClose={() => setEditingGlobal(null)} maxWidth="sm" fullWidth>
        <DialogTitle>Edit Global Variable</DialogTitle>
        <DialogContent>
          <TextField
            fullWidth
            label="Key"
            value={editingGlobal?.key || ""}
            onChange={(e) => setEditingGlobal(editingGlobal ? { ...editingGlobal, key: e.target.value } : null)}
            sx={{ mt: 1, mb: 2 }}
          />
          <TextField
            fullWidth
            label="Value"
            type={editingGlobal?.is_secret ? "password" : "text"}
            value={editingGlobal?.value || ""}
            onChange={(e) => setEditingGlobal(editingGlobal ? { ...editingGlobal, value: e.target.value } : null)}
            sx={{ mb: 2 }}
          />
          <FormControlLabel
            control={
              <Switch
                checked={editingGlobal?.is_secret || false}
                onChange={(e) => setEditingGlobal(editingGlobal ? { ...editingGlobal, is_secret: e.target.checked } : null)}
              />
            }
            label="Secret (value will be masked)"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingGlobal(null)}>Cancel</Button>
          <Button onClick={handleUpdateGlobal} variant="contained">
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
