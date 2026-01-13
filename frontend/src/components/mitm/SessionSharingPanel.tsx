import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Button,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  ListItemSecondaryAction,
  Avatar,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  FormControlLabel,
  Switch,
  Chip,
  Alert,
  Paper,
  Stack,
  Divider,
  Tooltip,
  Badge,
  InputAdornment,
} from '@mui/material';
import {
  Share as ShareIcon,
  People as PeopleIcon,
  Link as LinkIcon,
  ContentCopy as CopyIcon,
  Delete as DeleteIcon,
  PersonAdd as PersonAddIcon,
  ExitToApp as LeaveIcon,
  Visibility as ViewIcon,
  TouchApp as InteractIcon,
  Settings as FullIcon,
  Lock as LockIcon,
  LockOpen as UnlockIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { mitmClient, SharedSession } from '../../api/client';

interface SessionSharingPanelProps {
  proxyId: string;
  onSessionJoin?: (session: SharedSession) => void;
}

const SessionSharingPanel: React.FC<SessionSharingPanelProps> = ({
  proxyId,
  onSessionJoin,
}) => {
  const [sessions, setSessions] = useState<SharedSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [shareDialogOpen, setShareDialogOpen] = useState(false);
  const [selectedSession, setSelectedSession] = useState<SharedSession | null>(null);
  const [copySuccess, setCopySuccess] = useState(false);
  const [newSession, setNewSession] = useState({
    name: '',
    description: '',
    access_level: 'view' as 'view' | 'interact' | 'full',
    expires_hours: 24,
    enable_link_sharing: false,
  });
  const [shareUserId, setShareUserId] = useState('');

  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    try {
      setLoading(true);
      const data = await (mitmClient as any).listSharedSessions();
      setSessions(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateSession = async () => {
    if (!newSession.name.trim()) {
      setError('Please enter a session name');
      return;
    }
    try {
      const session = await (mitmClient as any).createSharedSession({
        proxy_id: proxyId,
        ...newSession,
      });
      setSessions([...sessions, session]);
      setCreateDialogOpen(false);
      setNewSession({
        name: '',
        description: '',
        access_level: 'view',
        expires_hours: 24,
        enable_link_sharing: false,
      });
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeleteSession = async (sessionId: string) => {
    try {
      await (mitmClient as any).deleteSharedSession(sessionId);
      setSessions(sessions.filter((s) => s.id !== sessionId));
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleJoinSession = async (session: SharedSession) => {
    try {
      await (mitmClient as any).joinSharedSession(session.id);
      if (onSessionJoin) {
        onSessionJoin(session);
      }
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleLeaveSession = async (sessionId: string) => {
    try {
      await (mitmClient as any).leaveSharedSession(sessionId);
      loadSessions();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleShareWithUser = async () => {
    if (!selectedSession || !shareUserId.trim()) {
      setError('Please enter a user ID');
      return;
    }
    try {
      await (mitmClient as any).shareSessionWithUser(selectedSession.id, shareUserId);
      setShareUserId('');
      setShareDialogOpen(false);
      loadSessions();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleCopyLink = async (link: string) => {
    try {
      await navigator.clipboard.writeText(link);
      setCopySuccess(true);
      setTimeout(() => setCopySuccess(false), 2000);
    } catch (err) {
      setError('Failed to copy link');
    }
  };

  const getAccessLevelIcon = (level: string) => {
    switch (level) {
      case 'view':
        return <ViewIcon />;
      case 'interact':
        return <InteractIcon />;
      case 'full':
        return <FullIcon />;
      default:
        return <ViewIcon />;
    }
  };

  const getAccessLevelColor = (level: string) => {
    switch (level) {
      case 'view':
        return 'info';
      case 'interact':
        return 'warning';
      case 'full':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatExpiry = (expiresAt: string | undefined) => {
    if (!expiresAt) return 'Never';
    const date = new Date(expiresAt);
    const now = new Date();
    const diff = date.getTime() - now.getTime();
    if (diff < 0) return 'Expired';
    if (diff < 3600000) return `${Math.round(diff / 60000)} minutes`;
    if (diff < 86400000) return `${Math.round(diff / 3600000)} hours`;
    return `${Math.round(diff / 86400000)} days`;
  };

  return (
    <Box>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {copySuccess && (
        <Alert severity="success" sx={{ mb: 2 }}>
          Link copied to clipboard!
        </Alert>
      )}

      <Paper sx={{ p: 2 }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
          <Stack direction="row" alignItems="center" spacing={2}>
            <PeopleIcon color="primary" />
            <Typography variant="h6">Session Sharing</Typography>
          </Stack>
          <Button
            variant="contained"
            startIcon={<ShareIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            Share Session
          </Button>
        </Stack>

        {sessions.length === 0 ? (
          <Typography color="text.secondary" align="center" sx={{ py: 4 }}>
            No shared sessions. Create one to collaborate with team members.
          </Typography>
        ) : (
          <List>
            {sessions.map((session) => (
              <Paper key={session.id} variant="outlined" sx={{ mb: 1 }}>
                <ListItem>
                  <ListItemAvatar>
                    <Badge
                      badgeContent={session.active_viewers}
                      color="success"
                      invisible={session.active_viewers === 0}
                    >
                      <Avatar sx={{ bgcolor: 'primary.main' }}>
                        {session.enable_link_sharing ? <UnlockIcon /> : <LockIcon />}
                      </Avatar>
                    </Badge>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Stack direction="row" alignItems="center" spacing={1}>
                        <Typography variant="subtitle1">{session.name}</Typography>
                        <Chip
                          size="small"
                          icon={getAccessLevelIcon(session.access_level)}
                          label={session.access_level}
                          color={getAccessLevelColor(session.access_level) as any}
                        />
                      </Stack>
                    }
                    secondary={
                      <Stack direction="row" spacing={2} sx={{ mt: 0.5 }}>
                        <Typography variant="caption">
                          Owner: {session.owner_name}
                        </Typography>
                        <Typography variant="caption">
                          {session.participants.length} participants
                        </Typography>
                        <Typography variant="caption">
                          <ScheduleIcon sx={{ fontSize: 12, mr: 0.5, verticalAlign: 'middle' }} />
                          Expires: {formatExpiry(session.expires_at)}
                        </Typography>
                      </Stack>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Stack direction="row" spacing={1}>
                      {session.share_link && (
                        <Tooltip title="Copy Share Link">
                          <IconButton
                            size="small"
                            onClick={() => handleCopyLink(session.share_link!)}
                          >
                            <LinkIcon />
                          </IconButton>
                        </Tooltip>
                      )}
                      <Tooltip title="Share with User">
                        <IconButton
                          size="small"
                          onClick={() => {
                            setSelectedSession(session);
                            setShareDialogOpen(true);
                          }}
                        >
                          <PersonAddIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Join Session">
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => handleJoinSession(session)}
                        >
                          <PeopleIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete Session">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => handleDeleteSession(session.id)}
                        >
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Stack>
                  </ListItemSecondaryAction>
                </ListItem>

                {session.description && (
                  <Box sx={{ px: 2, pb: 2 }}>
                    <Typography variant="body2" color="text.secondary">
                      {session.description}
                    </Typography>
                  </Box>
                )}

                {session.participants.length > 0 && (
                  <Box sx={{ px: 2, pb: 2 }}>
                    <Typography variant="caption" color="text.secondary" gutterBottom>
                      Participants:
                    </Typography>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
                      {session.participants.map((participant) => (
                        <Chip
                          key={participant}
                          size="small"
                          label={participant}
                          variant="outlined"
                        />
                      ))}
                    </Stack>
                  </Box>
                )}
              </Paper>
            ))}
          </List>
        )}
      </Paper>

      {/* Create Session Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Share Proxy Session</DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 2 }}>
            <TextField
              label="Session Name"
              value={newSession.name}
              onChange={(e) => setNewSession({ ...newSession, name: e.target.value })}
              fullWidth
              required
            />
            <TextField
              label="Description"
              value={newSession.description}
              onChange={(e) => setNewSession({ ...newSession, description: e.target.value })}
              fullWidth
              multiline
              rows={2}
            />
            <FormControl fullWidth>
              <InputLabel>Access Level</InputLabel>
              <Select
                value={newSession.access_level}
                onChange={(e) =>
                  setNewSession({
                    ...newSession,
                    access_level: e.target.value as 'view' | 'interact' | 'full',
                  })
                }
                label="Access Level"
              >
                <MenuItem value="view">
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <ViewIcon />
                    <Box>
                      <Typography>View Only</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Can only view traffic, cannot interact
                      </Typography>
                    </Box>
                  </Stack>
                </MenuItem>
                <MenuItem value="interact">
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <InteractIcon />
                    <Box>
                      <Typography>Interact</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Can view and replay requests
                      </Typography>
                    </Box>
                  </Stack>
                </MenuItem>
                <MenuItem value="full">
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <FullIcon />
                    <Box>
                      <Typography>Full Control</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Can modify rules and settings
                      </Typography>
                    </Box>
                  </Stack>
                </MenuItem>
              </Select>
            </FormControl>
            <TextField
              label="Expires In (hours)"
              type="number"
              value={newSession.expires_hours}
              onChange={(e) =>
                setNewSession({
                  ...newSession,
                  expires_hours: parseInt(e.target.value) || 24,
                })
              }
              fullWidth
              helperText="Set to 0 for no expiration"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={newSession.enable_link_sharing}
                  onChange={(e) =>
                    setNewSession({ ...newSession, enable_link_sharing: e.target.checked })
                  }
                />
              }
              label="Enable Link Sharing (anyone with the link can join)"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleCreateSession}
            variant="contained"
            disabled={!newSession.name}
          >
            Create Shared Session
          </Button>
        </DialogActions>
      </Dialog>

      {/* Share with User Dialog */}
      <Dialog
        open={shareDialogOpen}
        onClose={() => setShareDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Share with User</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Enter the user ID of the person you want to share this session with.
            </Typography>
            <TextField
              label="User ID"
              value={shareUserId}
              onChange={(e) => setShareUserId(e.target.value)}
              fullWidth
              placeholder="Enter user ID or email"
            />
            {selectedSession?.share_link && (
              <Box>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Or share this link:
                </Typography>
                <TextField
                  value={selectedSession.share_link}
                  fullWidth
                  InputProps={{
                    readOnly: true,
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => handleCopyLink(selectedSession.share_link!)}
                        >
                          <CopyIcon />
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />
              </Box>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShareDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleShareWithUser}
            variant="contained"
            disabled={!shareUserId}
          >
            Share
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default SessionSharingPanel;
