import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Slider,
  IconButton,
  Chip,
  Tooltip,
  Alert,
  Paper,
  Stack,
  LinearProgress,
} from '@mui/material';
import {
  Speed as SpeedIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  SignalCellular4Bar as FastIcon,
  SignalCellular1Bar as SlowIcon,
  SignalCellularOff as OfflineIcon,
  Tune as TuneIcon,
} from '@mui/icons-material';
import { mitmClient, ThrottleProfile, ThrottleProfileCreate } from '../../api/client';

interface ThrottleProfileSelectorProps {
  onThrottleChange?: (profile: ThrottleProfile | null) => void;
}

const ThrottleProfileSelector: React.FC<ThrottleProfileSelectorProps> = ({
  onThrottleChange,
}) => {
  const [profiles, setProfiles] = useState<ThrottleProfile[]>([]);
  const [activeProfile, setActiveProfile] = useState<ThrottleProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newProfile, setNewProfile] = useState<ThrottleProfileCreate>({
    name: '',
    description: '',
    bandwidth_kbps: 1000,
    latency_ms: 100,
    packet_loss_percent: 0,
    jitter_ms: 0,
  });

  useEffect(() => {
    loadProfiles();
    loadActiveProfile();
  }, []);

  const loadProfiles = async () => {
    try {
      const data = await (mitmClient as any).listThrottleProfiles();
      setProfiles(data);
    } catch (err: any) {
      setError(err.message);
    }
  };

  const loadActiveProfile = async () => {
    try {
      setLoading(true);
      const data = await (mitmClient as any).getActiveThrottle();
      setActiveProfile(data.active_profile);
      if (onThrottleChange) {
        onThrottleChange(data.active_profile);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleProfileChange = async (profileId: string) => {
    try {
      setLoading(true);
      if (profileId === 'none') {
        await (mitmClient as any).deactivateThrottle();
        setActiveProfile(null);
        if (onThrottleChange) {
          onThrottleChange(null);
        }
      } else {
        await (mitmClient as any).activateThrottle(profileId);
        const profile = profiles.find((p) => p.id === profileId) || null;
        setActiveProfile(profile);
        if (onThrottleChange) {
          onThrottleChange(profile);
        }
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateProfile = async () => {
    try {
      const created = await (mitmClient as any).createThrottleProfile(newProfile);
      setProfiles([...profiles, created]);
      setCreateDialogOpen(false);
      setNewProfile({
        name: '',
        description: '',
        bandwidth_kbps: 1000,
        latency_ms: 100,
        packet_loss_percent: 0,
        jitter_ms: 0,
      });
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeleteProfile = async (profileId: string) => {
    try {
      await (mitmClient as any).deleteThrottleProfile(profileId);
      setProfiles(profiles.filter((p) => p.id !== profileId));
      if (activeProfile?.id === profileId) {
        setActiveProfile(null);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const getProfileIcon = (profile: ThrottleProfile) => {
    if (profile.bandwidth_kbps === 0 && profile.latency_ms === 0) {
      return <FastIcon color="success" />;
    }
    if (profile.bandwidth_kbps === 0 && profile.packet_loss_percent === 100) {
      return <OfflineIcon color="error" />;
    }
    if (profile.bandwidth_kbps < 500) {
      return <SlowIcon color="warning" />;
    }
    return <SpeedIcon color="primary" />;
  };

  const formatBandwidth = (kbps: number) => {
    if (kbps === 0) return 'Unlimited';
    if (kbps >= 1000) return `${(kbps / 1000).toFixed(1)} Mbps`;
    return `${kbps} Kbps`;
  };

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Paper sx={{ p: 2 }}>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
          <TuneIcon color="primary" />
          <Typography variant="h6">Network Throttling</Typography>
        </Stack>

        {loading && <LinearProgress sx={{ mb: 2 }} />}

        <FormControl fullWidth sx={{ mb: 2 }}>
          <InputLabel>Throttle Profile</InputLabel>
          <Select
            value={activeProfile?.id || 'none'}
            onChange={(e) => handleProfileChange(e.target.value as string)}
            label="Throttle Profile"
            disabled={loading}
          >
            <MenuItem value="none">
              <Stack direction="row" alignItems="center" spacing={1}>
                <FastIcon color="success" />
                <span>No Throttling (Full Speed)</span>
              </Stack>
            </MenuItem>
            {profiles.map((profile) => (
              <MenuItem key={profile.id} value={profile.id}>
                <Stack direction="row" alignItems="center" spacing={1} sx={{ width: '100%' }}>
                  {getProfileIcon(profile)}
                  <Box sx={{ flex: 1 }}>
                    <Typography variant="body2">{profile.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {formatBandwidth(profile.bandwidth_kbps)} | {profile.latency_ms}ms latency
                    </Typography>
                  </Box>
                  {!profile.is_builtin && (
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteProfile(profile.id);
                      }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  )}
                </Stack>
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        {activeProfile && (
          <Box sx={{ mb: 2 }}>
            <Typography variant="body2" color="text.secondary" gutterBottom>
              Active Profile Details:
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              <Chip
                size="small"
                label={`Bandwidth: ${formatBandwidth(activeProfile.bandwidth_kbps)}`}
                color="primary"
                variant="outlined"
              />
              <Chip
                size="small"
                label={`Latency: ${activeProfile.latency_ms}ms`}
                color="secondary"
                variant="outlined"
              />
              <Chip
                size="small"
                label={`Packet Loss: ${activeProfile.packet_loss_percent}%`}
                color={activeProfile.packet_loss_percent > 0 ? 'warning' : 'default'}
                variant="outlined"
              />
              <Chip
                size="small"
                label={`Jitter: ${activeProfile.jitter_ms}ms`}
                variant="outlined"
              />
            </Stack>
          </Box>
        )}

        <Button
          startIcon={<AddIcon />}
          variant="outlined"
          onClick={() => setCreateDialogOpen(true)}
          fullWidth
        >
          Create Custom Profile
        </Button>
      </Paper>

      {/* Create Profile Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Create Custom Throttle Profile</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 2 }}>
            <TextField
              label="Profile Name"
              value={newProfile.name}
              onChange={(e) => setNewProfile({ ...newProfile, name: e.target.value })}
              fullWidth
              required
            />
            <TextField
              label="Description"
              value={newProfile.description}
              onChange={(e) => setNewProfile({ ...newProfile, description: e.target.value })}
              fullWidth
              multiline
              rows={2}
            />
            <Box>
              <Typography gutterBottom>
                Bandwidth: {formatBandwidth(newProfile.bandwidth_kbps || 0)}
              </Typography>
              <Slider
                value={newProfile.bandwidth_kbps || 0}
                onChange={(_, value) =>
                  setNewProfile({ ...newProfile, bandwidth_kbps: value as number })
                }
                min={0}
                max={10000}
                step={100}
                marks={[
                  { value: 0, label: '∞' },
                  { value: 500, label: '500K' },
                  { value: 1000, label: '1M' },
                  { value: 5000, label: '5M' },
                  { value: 10000, label: '10M' },
                ]}
              />
            </Box>
            <Box>
              <Typography gutterBottom>
                Latency: {newProfile.latency_ms}ms
              </Typography>
              <Slider
                value={newProfile.latency_ms || 0}
                onChange={(_, value) =>
                  setNewProfile({ ...newProfile, latency_ms: value as number })
                }
                min={0}
                max={2000}
                step={10}
                marks={[
                  { value: 0, label: '0' },
                  { value: 100, label: '100' },
                  { value: 500, label: '500' },
                  { value: 1000, label: '1s' },
                  { value: 2000, label: '2s' },
                ]}
              />
            </Box>
            <Box>
              <Typography gutterBottom>
                Packet Loss: {newProfile.packet_loss_percent}%
              </Typography>
              <Slider
                value={newProfile.packet_loss_percent || 0}
                onChange={(_, value) =>
                  setNewProfile({ ...newProfile, packet_loss_percent: value as number })
                }
                min={0}
                max={100}
                step={1}
                marks={[
                  { value: 0, label: '0%' },
                  { value: 25, label: '25%' },
                  { value: 50, label: '50%' },
                  { value: 75, label: '75%' },
                  { value: 100, label: '100%' },
                ]}
              />
            </Box>
            <Box>
              <Typography gutterBottom>
                Jitter: {newProfile.jitter_ms}ms
              </Typography>
              <Slider
                value={newProfile.jitter_ms || 0}
                onChange={(_, value) =>
                  setNewProfile({ ...newProfile, jitter_ms: value as number })
                }
                min={0}
                max={500}
                step={10}
                marks={[
                  { value: 0, label: '0' },
                  { value: 100, label: '100' },
                  { value: 250, label: '250' },
                  { value: 500, label: '500' },
                ]}
              />
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleCreateProfile}
            variant="contained"
            disabled={!newProfile.name}
          >
            Create
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default ThrottleProfileSelector;
