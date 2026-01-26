/**
 * Android Fuzzer Tab Component
 *
 * Integrated into the Binary Fuzzer for Android native library and IPC fuzzing.
 * Provides device management, native .so analysis, and Intent fuzzing.
 */

import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  TextField,
  Button,
  Grid,
  Chip,
  Alert,
  CircularProgress,
  LinearProgress,
  Divider,
  IconButton,
  Tooltip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  Badge,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Collapse,
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  BugReport,
  Memory,
  Refresh,
  Warning,
  CheckCircle,
  Info,
  Settings,
  PhoneAndroid,
  Cloud,
  CloudUpload,
  Smartphone,
  Apps,
  Extension,
  Notifications,
  Storage as StorageIcon,
  FlashOn,
  PowerSettingsNew,
  ExpandMore,
  ExpandLess,
  Security,
} from '@mui/icons-material';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip as RechartsTooltip } from 'recharts';

const API_URL = import.meta.env.VITE_API_URL || '/api';

// API helper
const api = {
  get: async (url: string, config?: { params?: Record<string, string> }) => {
    const queryString = config?.params ? '?' + new URLSearchParams(config.params).toString() : '';
    const resp = await fetch(`${API_URL}${url}${queryString}`);
    if (!resp.ok) throw new Error(await resp.text());
    return { data: await resp.json() };
  },
  post: async (url: string, data?: unknown, config?: { headers?: Record<string, string> }) => {
    const isFormData = data instanceof FormData;
    const resp = await fetch(`${API_URL}${url}`, {
      method: 'POST',
      headers: isFormData ? undefined : { 'Content-Type': 'application/json', ...config?.headers },
      body: isFormData ? data : data ? JSON.stringify(data) : undefined,
    });
    if (!resp.ok) throw new Error(await resp.text());
    return { data: await resp.json() };
  },
};

// Types
interface AndroidDevice {
  serial: string;
  state: string;
  model: string;
  manufacturer: string;
  android_version: string;
  sdk_version: number;
  abi: string;
  is_emulator: boolean;
  is_rooted: boolean;
  frida_server_running: boolean;
}

interface Emulator {
  name: string;
  serial: string;
  pid: number;
  state: string;
  port: number;
  adb_port: number;
  boot_completed: boolean;
  is_rooted: boolean;
  has_frida: boolean;
}

interface NativeLibrary {
  name: string;
  path: string;
  architecture: string;
  size: number;
  is_stripped: boolean;
  exports_count: number;
  dangerous_functions: string[];
  jni_functions: string[];
}

interface ExportedComponent {
  name: string;
  component_type: string;
  package_name: string;
  exported: boolean;
  permissions: string[];
}

interface AndroidCrash {
  crash_id: string;
  crash_type: string;
  severity: string;
  component: string;
  source: string;
  exception_or_signal: string;
  is_exploitable: boolean;
}

interface FuzzEvent {
  type: string;
  [key: string]: unknown;
}

// Props
interface AndroidFuzzerTabProps {
  onCrashFound?: (crash: AndroidCrash) => void;
}

const AndroidFuzzerTab: React.FC<AndroidFuzzerTabProps> = ({ onCrashFound }) => {
  const theme = useTheme();

  // Sub-tab state
  const [subTab, setSubTab] = useState(0);

  // Device state
  const [devices, setDevices] = useState<AndroidDevice[]>([]);
  const [emulators, setEmulators] = useState<Emulator[]>([]);
  const [avds, setAvds] = useState<string[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<string>('');

  // Loading and messages
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Package state
  const [packageName, setPackageName] = useState('');
  const [apkFile, setApkFile] = useState<File | null>(null);

  // Analysis results
  const [nativeLibraries, setNativeLibraries] = useState<NativeLibrary[]>([]);
  const [exportedComponents, setExportedComponents] = useState<ExportedComponent[]>([]);
  const [expandedSection, setExpandedSection] = useState<string | null>('devices');

  // Fuzzing state
  const [isFuzzing, setIsFuzzing] = useState(false);
  const [fuzzingStats, setFuzzingStats] = useState({
    intents_sent: 0,
    native_executions: 0,
    crashes: 0,
    unique_crashes: 0,
    anrs: 0,
  });
  const [crashes, setCrashes] = useState<AndroidCrash[]>([]);
  const [events, setEvents] = useState<FuzzEvent[]>([]);

  // Fuzzing config
  const [fuzzConfig, setFuzzConfig] = useState({
    fuzz_native: true,
    fuzz_intents: true,
    max_iterations: 5000,
    max_crashes: 50,
  });

  // WebSocket ref
  const wsRef = useRef<WebSocket | null>(null);

  // Fetch devices
  const fetchDevices = useCallback(async () => {
    try {
      const response = await api.get('/android/devices');
      setDevices(response.data);
    } catch (err) {
      console.error('Failed to fetch devices:', err);
    }
  }, []);

  // Fetch emulators
  const fetchEmulators = useCallback(async () => {
    try {
      const response = await api.get('/android/emulators');
      setEmulators(response.data);
    } catch (err) {
      console.error('Failed to fetch emulators:', err);
    }
  }, []);

  // Fetch AVDs
  const fetchAvds = useCallback(async () => {
    try {
      const response = await api.get('/android/avds');
      setAvds(response.data);
    } catch (err) {
      console.error('Failed to fetch AVDs:', err);
    }
  }, []);

  // Initial load
  useEffect(() => {
    fetchDevices();
    fetchEmulators();
    fetchAvds();

    const interval = setInterval(() => {
      fetchDevices();
      fetchEmulators();
    }, 15000);

    return () => clearInterval(interval);
  }, [fetchDevices, fetchEmulators, fetchAvds]);

  // Clear messages after delay
  useEffect(() => {
    if (success) {
      const timer = setTimeout(() => setSuccess(null), 5000);
      return () => clearTimeout(timer);
    }
  }, [success]);

  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => setError(null), 10000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  // Start FRIDA
  const startFrida = async (serial: string) => {
    setLoading(true);
    try {
      await api.post(`/android/devices/${serial}/frida/start`);
      setSuccess('FRIDA server started');
      fetchDevices();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start FRIDA');
    } finally {
      setLoading(false);
    }
  };

  // Stop FRIDA
  const stopFrida = async (serial: string) => {
    try {
      await api.post(`/android/devices/${serial}/frida/stop`);
      setSuccess('FRIDA server stopped');
      fetchDevices();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to stop FRIDA');
    }
  };

  // Start emulator
  const startEmulator = async (avdName: string) => {
    setLoading(true);
    try {
      const response = await api.post('/android/emulators/start', {
        avd_name: avdName,
        headless: true,
        writable_system: true,
      });
      setSuccess(`Emulator started: ${response.data.serial}`);
      fetchEmulators();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start emulator');
    } finally {
      setLoading(false);
    }
  };

  // Stop emulator
  const stopEmulator = async (serial: string) => {
    try {
      await api.post(`/android/emulators/${serial}/stop`);
      setSuccess('Emulator stopped');
      fetchEmulators();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to stop emulator');
    }
  };

  // Setup fuzzing environment
  const setupFuzzingEnv = async (serial: string) => {
    setLoading(true);
    try {
      const response = await api.post(`/android/emulators/${serial}/setup-fuzzing`);
      setSuccess(`Fuzzing environment ready: ${JSON.stringify(response.data.setup)}`);
      fetchDevices();
      fetchEmulators();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to setup environment');
    } finally {
      setLoading(false);
    }
  };

  // Handle APK upload
  const handleApkUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setApkFile(file);
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('file', file);
      await api.post('/android/apk/upload', formData);
      setSuccess(`APK uploaded: ${file.name}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to upload APK');
      setApkFile(null);
    } finally {
      setLoading(false);
    }
  };

  // Analyze native libraries
  const analyzeNativeLibraries = async () => {
    if (!selectedDevice || !packageName) {
      setError('Select a device and enter package name');
      return;
    }

    setLoading(true);
    try {
      const response = await api.get(`/android/packages/${packageName}/native-libraries`, {
        params: { serial: selectedDevice },
      });
      setNativeLibraries(response.data);
      setSuccess(`Found ${response.data.length} native libraries`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to analyze libraries');
    } finally {
      setLoading(false);
    }
  };

  // Analyze components
  const analyzeComponents = async () => {
    if (!selectedDevice || !packageName) {
      setError('Select a device and enter package name');
      return;
    }

    setLoading(true);
    try {
      const response = await api.get(`/android/packages/${packageName}/components`, {
        params: { serial: selectedDevice },
      });
      setExportedComponents(response.data);
      setSuccess(`Found ${response.data.length} exported components`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to analyze components');
    } finally {
      setLoading(false);
    }
  };

  // Start fuzzing
  const startFuzzing = async () => {
    if (!selectedDevice || !packageName) {
      setError('Select a device and enter package name');
      return;
    }

    setIsFuzzing(true);
    setCrashes([]);
    setEvents([]);
    setFuzzingStats({ intents_sent: 0, native_executions: 0, crashes: 0, unique_crashes: 0, anrs: 0 });

    try {
      // Create campaign
      const createResponse = await api.post('/android/campaign/create', {
        name: `Binary Fuzzer - ${packageName}`,
        target_type: 'package',
        target_path: packageName,
        device_serial: selectedDevice,
        use_emulator: false,
        fuzz_native_libraries: fuzzConfig.fuzz_native,
        fuzz_activities: fuzzConfig.fuzz_intents,
        fuzz_services: fuzzConfig.fuzz_intents,
        fuzz_receivers: fuzzConfig.fuzz_intents,
        fuzz_providers: fuzzConfig.fuzz_intents,
        max_iterations: fuzzConfig.max_iterations,
        max_crashes: fuzzConfig.max_crashes,
      });

      const campaignId = createResponse.data.campaign_id;

      // Connect WebSocket
      const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${wsProtocol}//${window.location.host}/android/campaign/ws/${campaignId}`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        handleFuzzEvent(data);
      };

      ws.onclose = () => {
        setIsFuzzing(false);
      };

      ws.onerror = () => {
        setError('WebSocket connection failed');
        setIsFuzzing(false);
      };

    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to start fuzzing');
      setIsFuzzing(false);
    }
  };

  // Handle fuzz event
  const handleFuzzEvent = (event: FuzzEvent) => {
    setEvents(prev => [...prev.slice(-50), event]);

    switch (event.type) {
      case 'stats':
        setFuzzingStats({
          intents_sent: (event.intents_sent as number) || 0,
          native_executions: (event.native_executions as number) || 0,
          crashes: (event.crashes as number) || 0,
          unique_crashes: (event.unique_crashes as number) || 0,
          anrs: (event.anrs as number) || 0,
        });
        break;

      case 'crash':
        const crash: AndroidCrash = {
          crash_id: event.crash_id as string,
          crash_type: event.crash_type as string,
          severity: event.severity as string,
          component: event.component as string,
          source: (event.source as string) || 'unknown',
          exception_or_signal: (event.exception as string) || '',
          is_exploitable: (event.is_exploitable as boolean) || false,
        };
        setCrashes(prev => [...prev, crash]);
        onCrashFound?.(crash);
        break;

      case 'campaign_completed':
      case 'error':
        setIsFuzzing(false);
        if (event.type === 'error') {
          setError(event.message as string);
        } else {
          setSuccess('Fuzzing campaign completed');
        }
        break;
    }
  };

  // Stop fuzzing
  const stopFuzzing = () => {
    wsRef.current?.close();
    setIsFuzzing(false);
    setSuccess('Fuzzing stopped');
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return theme.palette.error.main;
      case 'high': return theme.palette.warning.main;
      case 'medium': return theme.palette.info.main;
      default: return theme.palette.success.main;
    }
  };

  // Get component icon
  const getComponentIcon = (type: string) => {
    switch (type) {
      case 'activity': return <Apps fontSize="small" />;
      case 'service': return <Settings fontSize="small" />;
      case 'receiver': return <Notifications fontSize="small" />;
      case 'provider': return <StorageIcon fontSize="small" />;
      default: return <Extension fontSize="small" />;
    }
  };

  const allDevices = [
    ...devices.map(d => ({ ...d, type: 'device' as const })),
    ...emulators.map(e => ({
      serial: e.serial,
      model: e.name,
      android_version: 'Emulator',
      is_emulator: true,
      is_rooted: e.is_rooted,
      frida_server_running: e.has_frida,
      state: e.boot_completed ? 'device' : 'booting',
      type: 'emulator' as const
    }))
  ];

  return (
    <Box>
      {/* Sub-tabs */}
      <Tabs
        value={subTab}
        onChange={(_, v) => setSubTab(v)}
        sx={{ mb: 2, borderBottom: 1, borderColor: 'divider' }}
      >
        <Tab label="Devices" icon={<PhoneAndroid fontSize="small" />} iconPosition="start" />
        <Tab label="Analysis" icon={<Memory fontSize="small" />} iconPosition="start" />
        <Tab label="Fuzzing" icon={<BugReport fontSize="small" />} iconPosition="start" />
        <Tab
          label={
            <Badge badgeContent={crashes.length} color="error">
              Results
            </Badge>
          }
          icon={<Security fontSize="small" />}
          iconPosition="start"
        />
      </Tabs>

      {/* Messages */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert severity="success" onClose={() => setSuccess(null)} sx={{ mb: 2 }}>
          {success}
        </Alert>
      )}

      {/* Devices Sub-tab */}
      {subTab === 0 && (
        <Box>
          {/* Connected Devices */}
          <Paper sx={{ p: 2, mb: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="subtitle1" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PhoneAndroid color="primary" />
                Connected Devices & Emulators
              </Typography>
              <Button size="small" startIcon={<Refresh />} onClick={() => { fetchDevices(); fetchEmulators(); }}>
                Refresh
              </Button>
            </Box>

            {allDevices.length === 0 ? (
              <Alert severity="info">
                No devices connected. Connect via ADB or start an emulator below.
              </Alert>
            ) : (
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell padding="checkbox"></TableCell>
                      <TableCell>Device</TableCell>
                      <TableCell>Android</TableCell>
                      <TableCell>Status</TableCell>
                      <TableCell>FRIDA</TableCell>
                      <TableCell>Actions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {allDevices.map((device) => (
                      <TableRow
                        key={device.serial}
                        selected={selectedDevice === device.serial}
                        onClick={() => setSelectedDevice(device.serial)}
                        sx={{ cursor: 'pointer' }}
                      >
                        <TableCell padding="checkbox">
                          {device.is_emulator ? <Cloud fontSize="small" color="action" /> : <Smartphone fontSize="small" color="action" />}
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">{device.model || device.serial}</Typography>
                          <Typography variant="caption" color="text.secondary">{device.serial}</Typography>
                        </TableCell>
                        <TableCell>{device.android_version}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={device.state}
                            color={device.state === 'device' ? 'success' : 'warning'}
                          />
                          {device.is_rooted && <Chip size="small" label="Root" color="info" sx={{ ml: 0.5 }} />}
                        </TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={device.frida_server_running ? 'Running' : 'Off'}
                            color={device.frida_server_running ? 'success' : 'default'}
                          />
                        </TableCell>
                        <TableCell>
                          <Tooltip title={device.frida_server_running ? 'Stop FRIDA' : 'Start FRIDA'}>
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                device.frida_server_running ? stopFrida(device.serial) : startFrida(device.serial);
                              }}
                            >
                              {device.frida_server_running ? <Stop fontSize="small" /> : <PlayArrow fontSize="small" />}
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Setup Fuzzing Environment">
                            <IconButton
                              size="small"
                              onClick={(e) => { e.stopPropagation(); setupFuzzingEnv(device.serial); }}
                            >
                              <FlashOn fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          {device.is_emulator && (
                            <Tooltip title="Stop Emulator">
                              <IconButton
                                size="small"
                                onClick={(e) => { e.stopPropagation(); stopEmulator(device.serial); }}
                              >
                                <PowerSettingsNew fontSize="small" />
                              </IconButton>
                            </Tooltip>
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </Paper>

          {/* Available AVDs */}
          <Paper sx={{ p: 2 }}>
            <Typography variant="subtitle1" sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <Cloud color="primary" />
              Available AVDs (Emulators)
            </Typography>
            {avds.length === 0 ? (
              <Alert severity="info">No AVDs found. Create one using Android Studio.</Alert>
            ) : (
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {avds.map((avd) => (
                  <Chip
                    key={avd}
                    label={avd}
                    onClick={() => startEmulator(avd)}
                    icon={<PlayArrow />}
                    variant="outlined"
                    sx={{ cursor: 'pointer' }}
                  />
                ))}
              </Box>
            )}
          </Paper>
        </Box>
      )}

      {/* Analysis Sub-tab */}
      {subTab === 1 && (
        <Box>
          {/* Target Selection */}
          <Paper sx={{ p: 2, mb: 2 }}>
            <Typography variant="subtitle1" gutterBottom>Target Selection</Typography>
            <Grid container spacing={2} alignItems="center">
              <Grid item xs={12} md={4}>
                <FormControl fullWidth size="small">
                  <InputLabel>Device</InputLabel>
                  <Select
                    value={selectedDevice}
                    label="Device"
                    onChange={(e) => setSelectedDevice(e.target.value)}
                  >
                    {allDevices.map((d) => (
                      <MenuItem key={d.serial} value={d.serial}>
                        {d.is_emulator ? <Cloud fontSize="small" sx={{ mr: 1 }} /> : <Smartphone fontSize="small" sx={{ mr: 1 }} />}
                        {d.model || d.serial}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={12} md={4}>
                <TextField
                  fullWidth
                  size="small"
                  label="Package Name"
                  value={packageName}
                  onChange={(e) => setPackageName(e.target.value)}
                  placeholder="com.example.app"
                />
              </Grid>
              <Grid item xs={12} md={4}>
                <Button
                  variant="outlined"
                  component="label"
                  fullWidth
                  startIcon={<CloudUpload />}
                >
                  {apkFile ? apkFile.name.slice(0, 20) : 'Upload APK'}
                  <input type="file" hidden accept=".apk" onChange={handleApkUpload} />
                </Button>
              </Grid>
            </Grid>

            <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
              <Button
                variant="contained"
                size="small"
                startIcon={<Memory />}
                onClick={analyzeNativeLibraries}
                disabled={loading || !selectedDevice || !packageName}
              >
                Analyze Native Libs
              </Button>
              <Button
                variant="contained"
                size="small"
                startIcon={<Apps />}
                onClick={analyzeComponents}
                disabled={loading || !selectedDevice || !packageName}
              >
                Analyze Components
              </Button>
            </Box>
          </Paper>

          {/* Native Libraries */}
          {nativeLibraries.length > 0 && (
            <Paper sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle1" sx={{ mb: 1 }}>
                Native Libraries ({nativeLibraries.length})
              </Typography>
              <TableContainer sx={{ maxHeight: 250 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Name</TableCell>
                      <TableCell>Arch</TableCell>
                      <TableCell>Size</TableCell>
                      <TableCell>Exports</TableCell>
                      <TableCell>Dangerous</TableCell>
                      <TableCell>JNI</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {nativeLibraries.map((lib) => (
                      <TableRow key={lib.path}>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                            {lib.name}
                          </Typography>
                        </TableCell>
                        <TableCell>{lib.architecture}</TableCell>
                        <TableCell>{(lib.size / 1024).toFixed(0)} KB</TableCell>
                        <TableCell>{lib.exports_count}</TableCell>
                        <TableCell>
                          {lib.dangerous_functions.length > 0 ? (
                            <Tooltip title={lib.dangerous_functions.join(', ')}>
                              <Chip size="small" label={lib.dangerous_functions.length} color="error" />
                            </Tooltip>
                          ) : (
                            <Chip size="small" label="0" color="success" />
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip size="small" label={lib.jni_functions.length} variant="outlined" />
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          )}

          {/* Exported Components */}
          {exportedComponents.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle1" sx={{ mb: 1 }}>
                Exported Components ({exportedComponents.length})
              </Typography>
              <TableContainer sx={{ maxHeight: 250 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Type</TableCell>
                      <TableCell>Name</TableCell>
                      <TableCell>Permissions</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {exportedComponents.map((comp) => (
                      <TableRow key={comp.name}>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            {getComponentIcon(comp.component_type)}
                            <Typography variant="caption">{comp.component_type}</Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.7rem' }}>
                            {comp.name.split('/').pop()}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {comp.permissions.length > 0 ? (
                            <Chip size="small" label={comp.permissions.length} />
                          ) : (
                            <Chip size="small" label="None" color="warning" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Paper>
          )}
        </Box>
      )}

      {/* Fuzzing Sub-tab */}
      {subTab === 2 && (
        <Box>
          <Grid container spacing={2}>
            {/* Config */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle1" gutterBottom>Fuzzing Configuration</Typography>

                <FormControlLabel
                  control={
                    <Switch
                      checked={fuzzConfig.fuzz_native}
                      onChange={(e) => setFuzzConfig({ ...fuzzConfig, fuzz_native: e.target.checked })}
                    />
                  }
                  label="Fuzz Native Libraries (.so)"
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={fuzzConfig.fuzz_intents}
                      onChange={(e) => setFuzzConfig({ ...fuzzConfig, fuzz_intents: e.target.checked })}
                    />
                  }
                  label="Fuzz Intents (Activities, Services, Receivers)"
                />

                <Divider sx={{ my: 2 }} />

                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <TextField
                      fullWidth
                      size="small"
                      type="number"
                      label="Max Iterations"
                      value={fuzzConfig.max_iterations}
                      onChange={(e) => setFuzzConfig({ ...fuzzConfig, max_iterations: parseInt(e.target.value) || 5000 })}
                    />
                  </Grid>
                  <Grid item xs={6}>
                    <TextField
                      fullWidth
                      size="small"
                      type="number"
                      label="Max Crashes"
                      value={fuzzConfig.max_crashes}
                      onChange={(e) => setFuzzConfig({ ...fuzzConfig, max_crashes: parseInt(e.target.value) || 50 })}
                    />
                  </Grid>
                </Grid>

                <Box sx={{ mt: 3 }}>
                  {!isFuzzing ? (
                    <Button
                      variant="contained"
                      color="primary"
                      fullWidth
                      startIcon={<PlayArrow />}
                      onClick={startFuzzing}
                      disabled={loading || !selectedDevice || !packageName}
                    >
                      Start Android Fuzzing
                    </Button>
                  ) : (
                    <Button
                      variant="contained"
                      color="error"
                      fullWidth
                      startIcon={<Stop />}
                      onClick={stopFuzzing}
                    >
                      Stop Fuzzing
                    </Button>
                  )}
                </Box>

                {!selectedDevice && (
                  <Alert severity="warning" sx={{ mt: 2 }}>
                    Select a device in the Devices tab first
                  </Alert>
                )}
                {!packageName && (
                  <Alert severity="warning" sx={{ mt: 1 }}>
                    Enter a package name in the Analysis tab
                  </Alert>
                )}
              </Paper>
            </Grid>

            {/* Live Stats */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle1" gutterBottom>Live Statistics</Typography>

                {isFuzzing && <LinearProgress sx={{ mb: 2 }} />}

                <Grid container spacing={2}>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 1.5, textAlign: 'center', bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                      <Typography variant="h5" color="primary">{fuzzingStats.unique_crashes}</Typography>
                      <Typography variant="caption">Unique Crashes</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 1.5, textAlign: 'center', bgcolor: alpha(theme.palette.error.main, 0.1) }}>
                      <Typography variant="h5" color="error">{fuzzingStats.crashes}</Typography>
                      <Typography variant="caption">Total Crashes</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 1.5, textAlign: 'center' }}>
                      <Typography variant="h5">{fuzzingStats.native_executions}</Typography>
                      <Typography variant="caption">Native Executions</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 1.5, textAlign: 'center' }}>
                      <Typography variant="h5">{fuzzingStats.intents_sent}</Typography>
                      <Typography variant="caption">Intents Sent</Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6}>
                    <Paper sx={{ p: 1.5, textAlign: 'center', bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                      <Typography variant="h5" color="warning.main">{fuzzingStats.anrs}</Typography>
                      <Typography variant="caption">ANRs</Typography>
                    </Paper>
                  </Grid>
                </Grid>
              </Paper>

              {/* Recent Events */}
              <Paper sx={{ p: 2, mt: 2, maxHeight: 200, overflow: 'auto' }}>
                <Typography variant="subtitle2" gutterBottom>Recent Events</Typography>
                {events.slice(-10).reverse().map((event, idx) => (
                  <Box key={idx} sx={{ py: 0.5, borderBottom: '1px solid', borderColor: 'divider', fontSize: '0.75rem' }}>
                    <Chip size="small" label={event.type} sx={{ mr: 1 }} />
                    {(event.message as string) || (event.component as string) || ''}
                  </Box>
                ))}
                {events.length === 0 && <Typography variant="body2" color="text.secondary">No events yet</Typography>}
              </Paper>
            </Grid>
          </Grid>
        </Box>
      )}

      {/* Results Sub-tab */}
      {subTab === 3 && (
        <Box>
          {crashes.length === 0 ? (
            <Alert severity="info">No crashes found yet. Run fuzzing to discover vulnerabilities.</Alert>
          ) : (
            <>
              <TableContainer component={Paper}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>ID</TableCell>
                      <TableCell>Type</TableCell>
                      <TableCell>Severity</TableCell>
                      <TableCell>Source</TableCell>
                      <TableCell>Component</TableCell>
                      <TableCell>Exploitable</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {crashes.map((crash) => (
                      <TableRow key={crash.crash_id}>
                        <TableCell>
                          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>{crash.crash_id}</Typography>
                        </TableCell>
                        <TableCell>{crash.crash_type}</TableCell>
                        <TableCell>
                          <Chip
                            size="small"
                            label={crash.severity}
                            sx={{ bgcolor: alpha(getSeverityColor(crash.severity), 0.2), color: getSeverityColor(crash.severity) }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip size="small" label={crash.source} variant="outlined" />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {crash.component}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          {crash.is_exploitable ? (
                            <Chip size="small" label="Yes" color="error" />
                          ) : (
                            <Chip size="small" label="No" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>

              {/* Severity chart */}
              {crashes.length > 0 && (
                <Paper sx={{ p: 2, mt: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>Severity Distribution</Typography>
                  <ResponsiveContainer width="100%" height={200}>
                    <PieChart>
                      <Pie
                        data={[
                          { name: 'Critical', value: crashes.filter(c => c.severity === 'critical').length },
                          { name: 'High', value: crashes.filter(c => c.severity === 'high').length },
                          { name: 'Medium', value: crashes.filter(c => c.severity === 'medium').length },
                          { name: 'Low', value: crashes.filter(c => c.severity === 'low').length },
                        ].filter(d => d.value > 0)}
                        cx="50%"
                        cy="50%"
                        outerRadius={60}
                        dataKey="value"
                        label={({ name, value }) => `${name}: ${value}`}
                      >
                        <Cell fill={theme.palette.error.main} />
                        <Cell fill={theme.palette.warning.main} />
                        <Cell fill={theme.palette.info.main} />
                        <Cell fill={theme.palette.success.main} />
                      </Pie>
                      <RechartsTooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </Paper>
              )}
            </>
          )}
        </Box>
      )}

      {/* Loading overlay */}
      {loading && (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      )}
    </Box>
  );
};

export default AndroidFuzzerTab;
