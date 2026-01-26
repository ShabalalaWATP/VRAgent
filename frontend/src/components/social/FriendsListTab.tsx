import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Box,
  Typography,
  Avatar,
  Button,
  IconButton,
  CircularProgress,
  Alert,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  ListItemIcon,
  Tooltip,
  TextField,
  Paper,
  Fade,
  Skeleton,
  alpha,
} from '@mui/material';
import {
  Chat as ChatIcon,
  MoreVert as MoreIcon,
  PersonRemove as RemoveIcon,
  People as PeopleIcon,
  Note as NoteIcon,
  Save as SaveIcon,
  Circle as CircleIcon,
} from '@mui/icons-material';
import { socialApi, Friend, getAuthHeadersNoContentType } from '../../api/client';
import { PresenceIndicator, PresenceStatus } from './PresenceIndicator';

interface PresenceData {
  user_id: number;
  status: PresenceStatus;
  custom_status?: string;
  status_emoji?: string;
  last_seen_at?: string;
}

interface FriendsListTabProps {
  onStartChat: () => void;
}

export default function FriendsListTab({ onStartChat }: FriendsListTabProps) {
  const [contacts, setContacts] = useState<Friend[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedContact, setSelectedContact] = useState<Friend | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [removing, setRemoving] = useState(false);

  // Notes state
  const [noteDialogOpen, setNoteDialogOpen] = useState(false);
  const [noteContent, setNoteContent] = useState('');
  const [noteLoading, setNoteLoading] = useState(false);
  const [noteSaving, setNoteSaving] = useState(false);
  const [userNotes, setUserNotes] = useState<Record<number, string>>({});

  // Presence state
  const [presenceMap, setPresenceMap] = useState<Record<number, PresenceData>>({});
  const [presenceLoading, setPresenceLoading] = useState(false);
  const [presenceError, setPresenceError] = useState<string | null>(null);

  useEffect(() => {
    loadContacts();
  }, []);

  // Memoize contact IDs to prevent excessive polling
  const contactIds = useMemo(
    () => contacts.map(c => c.user_id).join(','),
    [contacts]
  );

  // Load presence with retry logic
  const loadContactsPresence = useCallback(async (retryCount = 0) => {
    setPresenceLoading(true);
    setPresenceError(null);
    try {
      const response = await fetch('/api/social/presence/friends/all', {
        headers: getAuthHeadersNoContentType(),
      });
      if (response.ok) {
        const data = await response.json();
        const map: Record<number, PresenceData> = {};
        // Fix: Backend returns 'users' not 'presences'
        data.users?.forEach((p: PresenceData) => {
          map[p.user_id] = p;
        });
        setPresenceMap(map);
        setPresenceError(null);
      } else if (retryCount < 2) {
        // Retry with exponential backoff
        setTimeout(() => loadContactsPresence(retryCount + 1), 1000 * (retryCount + 1));
        return;
      } else {
        setPresenceError('Failed to load presence data');
      }
    } catch (err) {
      console.error('Failed to load presence:', err);
      if (retryCount < 2) {
        // Retry with exponential backoff
        setTimeout(() => loadContactsPresence(retryCount + 1), 1000 * (retryCount + 1));
        return;
      }
      setPresenceError('Failed to load presence data');
    } finally {
      setPresenceLoading(false);
    }
  }, []);

  // Load presence for all contacts when contact IDs change
  useEffect(() => {
    if (contactIds) {
      loadContactsPresence();
    }
  }, [contactIds, loadContactsPresence]);

  const loadContacts = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await socialApi.getFriends();
      setContacts(result.friends);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load contacts');
    } finally {
      setLoading(false);
    }
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, contact: Friend) => {
    setAnchorEl(event.currentTarget);
    setSelectedContact(contact);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleRemoveContact = async () => {
    if (!selectedContact) return;

    setRemoving(true);
    setError('');
    try {
      await socialApi.removeFriend(selectedContact.user_id);
      setContacts(contacts.filter(c => c.user_id !== selectedContact.user_id));
      setConfirmOpen(false);
      handleMenuClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove contact');
    } finally {
      setRemoving(false);
    }
  };

  const handleStartChat = async (contact: Friend) => {
    try {
      await socialApi.createConversation(contact.user_id);
      onStartChat();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start conversation');
    }
  };

  const handleOpenNoteDialog = async (contact: Friend) => {
    setSelectedContact(contact);
    setNoteDialogOpen(true);
    setNoteLoading(true);
    handleMenuClose();

    try {
      if (userNotes[contact.user_id] !== undefined) {
        setNoteContent(userNotes[contact.user_id]);
      } else {
        const note = await socialApi.getNoteForUser(contact.user_id);
        setNoteContent(note?.content || '');
        setUserNotes(prev => ({ ...prev, [contact.user_id]: note?.content || '' }));
      }
    } catch (err) {
      setNoteContent('');
    } finally {
      setNoteLoading(false);
    }
  };

  const handleSaveNote = async () => {
    if (!selectedContact) return;

    setNoteSaving(true);
    try {
      if (noteContent.trim()) {
        await socialApi.createOrUpdateNote(selectedContact.user_id, noteContent.trim());
        setUserNotes(prev => ({ ...prev, [selectedContact.user_id]: noteContent.trim() }));
      } else if (userNotes[selectedContact.user_id]) {
        await socialApi.deleteNote(selectedContact.user_id);
        setUserNotes(prev => ({ ...prev, [selectedContact.user_id]: '' }));
      }
      setNoteDialogOpen(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save note');
    } finally {
      setNoteSaving(false);
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  };

  const formatLastSeen = (dateStr?: string) => {
    if (!dateStr) return null;
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 5) return 'Active now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return formatDate(dateStr);
  };

  const getPresenceColor = (status: PresenceStatus) => {
    switch (status) {
      case 'online': return 'success.main';
      case 'away': return 'warning.main';
      case 'busy':
      case 'dnd': return 'error.main';
      default: return 'text.disabled';
    }
  };

  const renderContactCard = (contact: Friend, index: number) => {
    const presence = presenceMap[contact.user_id];
    const lastSeen = formatLastSeen(contact.last_login);

    return (
      <Fade in key={contact.id} style={{ transitionDelay: `${index * 30}ms` }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 2,
            p: 2,
            borderRadius: 2,
            bgcolor: 'background.paper',
            transition: 'all 0.2s ease',
            '&:hover': {
              bgcolor: (theme) => alpha(theme.palette.primary.main, 0.04),
              '& .contact-actions': {
                opacity: 1,
              },
            },
          }}
        >
          <PresenceIndicator
            status={presence?.status || 'offline'}
            customStatus={presence?.custom_status}
            statusEmoji={presence?.status_emoji}
          >
            <Avatar
              src={contact.avatar_url}
              sx={{
                width: 48,
                height: 48,
                bgcolor: 'primary.main',
                fontSize: '1.1rem',
                fontWeight: 600,
              }}
            >
              {contact.username.charAt(0).toUpperCase()}
            </Avatar>
          </PresenceIndicator>

          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="subtitle2" fontWeight={600} noWrap>
                {contact.username}
              </Typography>
              {(contact.first_name || contact.last_name) && (
                <Typography variant="body2" color="text.secondary" noWrap>
                  {contact.first_name} {contact.last_name}
                </Typography>
              )}
              {presence?.custom_status && (
                <Typography
                  variant="caption"
                  color="text.secondary"
                  sx={{
                    fontStyle: 'italic',
                    bgcolor: (theme) => alpha(theme.palette.action.hover, 0.5),
                    px: 1,
                    py: 0.25,
                    borderRadius: 1,
                  }}
                >
                  {presence.status_emoji} {presence.custom_status}
                </Typography>
              )}
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mt: 0.25 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <CircleIcon sx={{ fontSize: 8, color: getPresenceColor(presence?.status || 'offline') }} />
                <Typography variant="caption" color="text.secondary">
                  {lastSeen || 'Offline'}
                </Typography>
              </Box>
              {contact.bio && (
                <>
                  <Typography variant="caption" color="text.disabled">•</Typography>
                  <Typography
                    variant="caption"
                    color="text.secondary"
                    sx={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {contact.bio}
                  </Typography>
                </>
              )}
            </Box>
          </Box>

          <Box
            className="contact-actions"
            sx={{
              display: 'flex',
              gap: 0.5,
              opacity: { xs: 1, sm: 0.5 },
              transition: 'opacity 0.2s',
            }}
          >
            <Tooltip title="Message">
              <IconButton
                size="small"
                onClick={() => handleStartChat(contact)}
                sx={{
                  bgcolor: (theme) => alpha(theme.palette.primary.main, 0.1),
                  color: 'primary.main',
                  '&:hover': {
                    bgcolor: (theme) => alpha(theme.palette.primary.main, 0.2),
                  },
                }}
              >
                <ChatIcon fontSize="small" />
              </IconButton>
            </Tooltip>
            <IconButton
              size="small"
              onClick={(e) => handleMenuOpen(e, contact)}
              sx={{
                '&:hover': {
                  bgcolor: (theme) => alpha(theme.palette.action.hover, 0.8),
                },
              }}
            >
              <MoreIcon fontSize="small" />
            </IconButton>
          </Box>
        </Box>
      </Fade>
    );
  };

  const renderSkeletons = () => (
    <>
      {Array.from({ length: 5 }).map((_, i) => (
        <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 2, p: 2 }}>
          <Skeleton variant="circular" width={48} height={48} />
          <Box sx={{ flex: 1 }}>
            <Skeleton variant="text" width="35%" height={24} />
            <Skeleton variant="text" width="50%" height={18} />
          </Box>
          <Skeleton variant="rounded" width={32} height={32} />
        </Box>
      ))}
    </>
  );

  return (
    <Box sx={{ px: 3, py: 1 }}>
      {error && (
        <Fade in>
          <Alert
            severity="error"
            sx={{ mb: 2, borderRadius: 2 }}
            onClose={() => setError('')}
          >
            {error}
          </Alert>
        </Fade>
      )}

      <Paper
        elevation={0}
        sx={{
          borderRadius: 3,
          bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
          border: '1px solid',
          borderColor: 'divider',
          overflow: 'hidden',
        }}
      >
        {/* Header */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            p: 2,
            borderBottom: '1px solid',
            borderColor: 'divider',
            bgcolor: (theme) => alpha(theme.palette.background.default, 0.5),
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Box
              sx={{
                p: 1,
                borderRadius: 2,
                bgcolor: (theme) => alpha(theme.palette.primary.main, 0.1),
                display: 'flex',
              }}
            >
              <PeopleIcon color="primary" fontSize="small" />
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={600}>
                Contacts
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {loading ? 'Loading...' : `${contacts.length} contact${contacts.length !== 1 ? 's' : ''}`}
              </Typography>
            </Box>
          </Box>
        </Box>

        {/* Contact List */}
        <Box sx={{ p: 1 }}>
          {loading ? (
            renderSkeletons()
          ) : contacts.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <PeopleIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
              <Typography color="text.secondary">
                No contacts yet
              </Typography>
              <Typography variant="caption" color="text.disabled">
                Search for users to connect
              </Typography>
            </Box>
          ) : (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              {contacts.map((contact, index) => renderContactCard(contact, index))}
            </Box>
          )}
        </Box>
      </Paper>

      {/* Options Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
        PaperProps={{
          sx: {
            borderRadius: 2,
            minWidth: 160,
            boxShadow: '0 4px 20px rgba(0,0,0,0.1)',
          },
        }}
      >
        <MenuItem onClick={() => selectedContact && handleOpenNoteDialog(selectedContact)}>
          <ListItemIcon>
            <NoteIcon fontSize="small" color="primary" />
          </ListItemIcon>
          <Typography variant="body2">Private Note</Typography>
        </MenuItem>
        <MenuItem
          onClick={() => { setConfirmOpen(true); handleMenuClose(); }}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon>
            <RemoveIcon fontSize="small" color="error" />
          </ListItemIcon>
          <Typography variant="body2">Remove</Typography>
        </MenuItem>
      </Menu>

      {/* Confirm Remove Dialog */}
      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        PaperProps={{ sx: { borderRadius: 3, p: 1 } }}
      >
        <DialogTitle>
          <Typography variant="h6" fontWeight={600}>
            Remove Contact
          </Typography>
        </DialogTitle>
        <DialogContent>
          <Typography>
            Remove <strong>{selectedContact?.username}</strong> from your contacts?
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            You can add them again later.
          </Typography>
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setConfirmOpen(false)} sx={{ textTransform: 'none' }}>
            Cancel
          </Button>
          <Button
            color="error"
            variant="contained"
            onClick={handleRemoveContact}
            disabled={removing}
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              boxShadow: 'none',
            }}
          >
            {removing ? <CircularProgress size={20} color="inherit" /> : 'Remove'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Note Dialog */}
      <Dialog
        open={noteDialogOpen}
        onClose={() => setNoteDialogOpen(false)}
        maxWidth="sm"
        fullWidth
        PaperProps={{ sx: { borderRadius: 3, p: 1 } }}
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1.5, pb: 1 }}>
          <Box
            sx={{
              p: 1,
              borderRadius: 2,
              bgcolor: (theme) => alpha(theme.palette.primary.main, 0.1),
              display: 'flex',
            }}
          >
            <NoteIcon color="primary" fontSize="small" />
          </Box>
          <Box>
            <Typography variant="h6" fontWeight={600}>
              Note about {selectedContact?.username}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Only you can see this
            </Typography>
          </Box>
        </DialogTitle>
        <DialogContent>
          {noteLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress size={24} />
            </Box>
          ) : (
            <TextField
              fullWidth
              multiline
              rows={4}
              placeholder="Write your private note here..."
              value={noteContent}
              onChange={(e) => setNoteContent(e.target.value)}
              sx={{
                '& .MuiOutlinedInput-root': {
                  borderRadius: 2,
                },
              }}
            />
          )}
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setNoteDialogOpen(false)} sx={{ textTransform: 'none' }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSaveNote}
            disabled={noteSaving || noteLoading}
            startIcon={noteSaving ? <CircularProgress size={16} color="inherit" /> : <SaveIcon />}
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              boxShadow: 'none',
            }}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
