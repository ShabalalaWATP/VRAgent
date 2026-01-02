import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
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
  Chip,
  TextField,
} from '@mui/material';
import {
  Chat as ChatIcon,
  MoreVert as MoreIcon,
  PersonRemove as RemoveIcon,
  Person as PersonIcon,
  AccessTime as TimeIcon,
  Note as NoteIcon,
  Save as SaveIcon,
} from '@mui/icons-material';
import { socialApi, Friend, FriendsListResponse, UserNote } from '../../api/client';
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
  const [friends, setFriends] = useState<Friend[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedFriend, setSelectedFriend] = useState<Friend | null>(null);
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

  useEffect(() => {
    loadFriends();
  }, []);
  
  // Load presence for all friends
  useEffect(() => {
    if (friends.length > 0) {
      loadFriendsPresence();
    }
  }, [friends]);
  
  const loadFriendsPresence = async () => {
    try {
      const response = await fetch('/api/social/presence/friends/all', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        const map: Record<number, PresenceData> = {};
        data.presences?.forEach((p: PresenceData) => {
          map[p.user_id] = p;
        });
        setPresenceMap(map);
      }
    } catch (err) {
      console.error('Failed to load presence:', err);
    }
  };

  const loadFriends = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await socialApi.getFriends();
      setFriends(result.friends);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load friends');
    } finally {
      setLoading(false);
    }
  };

  const handleMenuOpen = (event: React.MouseEvent<HTMLElement>, friend: Friend) => {
    setAnchorEl(event.currentTarget);
    setSelectedFriend(friend);
  };

  const handleMenuClose = () => {
    setAnchorEl(null);
  };

  const handleRemoveFriend = async () => {
    if (!selectedFriend) return;
    
    setRemoving(true);
    setError('');
    try {
      await socialApi.removeFriend(selectedFriend.user_id);
      setFriends(friends.filter(f => f.user_id !== selectedFriend.user_id));
      setConfirmOpen(false);
      handleMenuClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove friend');
    } finally {
      setRemoving(false);
    }
  };

  const handleStartChat = async (friend: Friend) => {
    try {
      await socialApi.createConversation(friend.user_id);
      onStartChat();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start conversation');
    }
  };

  const handleOpenNoteDialog = async (friend: Friend) => {
    setSelectedFriend(friend);
    setNoteDialogOpen(true);
    setNoteLoading(true);
    handleMenuClose();
    
    try {
      // Check if we already have the note cached
      if (userNotes[friend.user_id] !== undefined) {
        setNoteContent(userNotes[friend.user_id]);
      } else {
        const note = await socialApi.getNoteForUser(friend.user_id);
        setNoteContent(note?.content || '');
        setUserNotes(prev => ({ ...prev, [friend.user_id]: note?.content || '' }));
      }
    } catch (err) {
      // No note exists yet
      setNoteContent('');
    } finally {
      setNoteLoading(false);
    }
  };

  const handleSaveNote = async () => {
    if (!selectedFriend) return;
    
    setNoteSaving(true);
    try {
      if (noteContent.trim()) {
        await socialApi.createOrUpdateNote(selectedFriend.user_id, noteContent.trim());
        setUserNotes(prev => ({ ...prev, [selectedFriend.user_id]: noteContent.trim() }));
      } else if (userNotes[selectedFriend.user_id]) {
        // Delete note if content is empty
        await socialApi.deleteNote(selectedFriend.user_id);
        setUserNotes(prev => ({ ...prev, [selectedFriend.user_id]: '' }));
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

  const formatLastLogin = (dateStr?: string) => {
    if (!dateStr) return 'Never';
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 5) return 'Online now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days < 7) return `${days}d ago`;
    return formatDate(dateStr);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box sx={{ px: 3 }}>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {friends.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <PersonIcon sx={{ fontSize: 64, color: 'text.disabled', mb: 2 }} />
          <Typography color="text.secondary">
            No contacts yet. Search for users to connect!
          </Typography>
        </Box>
      )}

      {friends.length > 0 && (
        <>
          <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>
            {friends.length} contact{friends.length !== 1 ? 's' : ''}
          </Typography>
          <List>
            {friends.map((friend) => (
              <ListItem
                key={friend.id}
                sx={{
                  border: '1px solid',
                  borderColor: 'divider',
                  borderRadius: 1,
                  mb: 1,
                }}
                secondaryAction={
                  <Box sx={{ display: 'flex', gap: 1 }}>
                    <Tooltip title="Send Message">
                      <IconButton color="primary" onClick={() => handleStartChat(friend)}>
                        <ChatIcon />
                      </IconButton>
                    </Tooltip>
                    <IconButton onClick={(e) => handleMenuOpen(e, friend)}>
                      <MoreIcon />
                    </IconButton>
                  </Box>
                }
              >
                <ListItemAvatar>
                  <PresenceIndicator 
                    status={presenceMap[friend.user_id]?.status || 'offline'}
                    customStatus={presenceMap[friend.user_id]?.custom_status}
                    statusEmoji={presenceMap[friend.user_id]?.status_emoji}
                  >
                    <Avatar
                      src={friend.avatar_url}
                      sx={{ bgcolor: 'primary.main' }}
                    >
                      {friend.username.charAt(0).toUpperCase()}
                    </Avatar>
                  </PresenceIndicator>
                </ListItemAvatar>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle1" fontWeight={500}>
                        {friend.username}
                      </Typography>
                      {(friend.first_name || friend.last_name) && (
                        <Typography variant="body2" color="text.secondary">
                          ({friend.first_name} {friend.last_name})
                        </Typography>
                      )}
                      {presenceMap[friend.user_id]?.custom_status && (
                        <Typography variant="body2" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                          {presenceMap[friend.user_id]?.status_emoji} {presenceMap[friend.user_id]?.custom_status}
                        </Typography>
                      )}
                    </Box>
                  }
                  secondary={
                    <Box>
                      {friend.bio && (
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 0.5 }}>
                          {friend.bio}
                        </Typography>
                      )}
                      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                        <Typography variant="caption" color="text.secondary">
                          Connected since {formatDate(friend.friends_since)}
                        </Typography>
                        {friend.last_login && (
                          <Typography variant="caption" color="text.secondary">
                            • Last seen: {formatLastLogin(friend.last_login)}
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  }
                />
              </ListItem>
            ))}
          </List>
        </>
      )}

      {/* Options Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleMenuClose}
      >
        <MenuItem onClick={() => selectedFriend && handleOpenNoteDialog(selectedFriend)}>
          <ListItemIcon>
            <NoteIcon fontSize="small" color="primary" />
          </ListItemIcon>
          <Typography>Private Note</Typography>
        </MenuItem>
        <MenuItem onClick={() => { setConfirmOpen(true); handleMenuClose(); }}>
          <ListItemIcon>
            <RemoveIcon fontSize="small" color="error" />
          </ListItemIcon>
          <Typography color="error">Remove Contact</Typography>
        </MenuItem>
      </Menu>

      {/* Confirm Remove Dialog */}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)}>
        <DialogTitle>Remove Contact</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to remove <strong>{selectedFriend?.username}</strong> from your contacts?
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmOpen(false)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={handleRemoveFriend}
            disabled={removing}
            startIcon={removing ? <CircularProgress size={16} /> : undefined}
          >
            Remove
          </Button>
        </DialogActions>
      </Dialog>

      {/* Note Dialog */}
      <Dialog 
        open={noteDialogOpen} 
        onClose={() => setNoteDialogOpen(false)} 
        maxWidth="sm" 
        fullWidth
      >
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <NoteIcon color="primary" />
          Private Note about {selectedFriend?.username}
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            This note is private and only visible to you. Use it to remember details about this person.
          </Typography>
          {noteLoading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
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
            />
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setNoteDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveNote}
            disabled={noteSaving || noteLoading}
            startIcon={noteSaving ? <CircularProgress size={16} /> : <SaveIcon />}
          >
            Save Note
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
