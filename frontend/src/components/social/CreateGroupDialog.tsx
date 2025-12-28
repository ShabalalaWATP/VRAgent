import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Checkbox,
  CircularProgress,
  Alert,
  Chip,
} from '@mui/material';
import {
  Group as GroupIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { socialApi, Friend, ConversationSummary } from '../../api/client';

interface CreateGroupDialogProps {
  open: boolean;
  onClose: () => void;
  onGroupCreated: (group: ConversationSummary) => void;
}

export default function CreateGroupDialog({ open, onClose, onGroupCreated }: CreateGroupDialogProps) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [friends, setFriends] = useState<Friend[]>([]);
  const [selectedFriends, setSelectedFriends] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingFriends, setLoadingFriends] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (open) {
      loadFriends();
      // Reset form
      setName('');
      setDescription('');
      setSelectedFriends([]);
      setError('');
    }
  }, [open]);

  const loadFriends = async () => {
    setLoadingFriends(true);
    try {
      const result = await socialApi.getFriends();
      setFriends(result.friends);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load friends');
    } finally {
      setLoadingFriends(false);
    }
  };

  const toggleFriend = (friendId: number) => {
    setSelectedFriends(prev => 
      prev.includes(friendId) 
        ? prev.filter(id => id !== friendId)
        : [...prev, friendId]
    );
  };

  const handleCreate = async () => {
    if (!name.trim()) {
      setError('Please enter a group name');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const group = await socialApi.createGroup({
        name: name.trim(),
        description: description.trim() || undefined,
        participant_ids: selectedFriends,
      });
      onGroupCreated(group);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create group');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <GroupIcon color="primary" />
          Create Group Chat
        </Box>
      </DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        <TextField
          fullWidth
          label="Group Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          margin="normal"
          required
          inputProps={{ maxLength: 100 }}
        />

        <TextField
          fullWidth
          label="Description (optional)"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          margin="normal"
          multiline
          rows={2}
          inputProps={{ maxLength: 500 }}
        />

        <Typography variant="subtitle2" sx={{ mt: 2, mb: 1 }}>
          Add Friends ({selectedFriends.length} selected)
        </Typography>

        {selectedFriends.length > 0 && (
          <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mb: 2 }}>
            {selectedFriends.map(id => {
              const friend = friends.find(f => f.user_id === id);
              return friend ? (
                <Chip
                  key={id}
                  label={friend.username}
                  size="small"
                  onDelete={() => toggleFriend(id)}
                  avatar={<Avatar src={friend.avatar_url}>{friend.username[0]}</Avatar>}
                />
              ) : null;
            })}
          </Box>
        )}

        {loadingFriends ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
            <CircularProgress size={24} />
          </Box>
        ) : friends.length === 0 ? (
          <Typography color="text.secondary" sx={{ py: 2, textAlign: 'center' }}>
            No friends to add. Add some friends first!
          </Typography>
        ) : (
          <List sx={{ maxHeight: 250, overflow: 'auto', border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
            {friends.map(friend => (
              <ListItem
                key={friend.user_id}
                dense
                button
                onClick={() => toggleFriend(friend.user_id)}
              >
                <Checkbox
                  edge="start"
                  checked={selectedFriends.includes(friend.user_id)}
                  tabIndex={-1}
                  disableRipple
                />
                <ListItemAvatar>
                  <Avatar src={friend.avatar_url} sx={{ width: 32, height: 32 }}>
                    {friend.username[0].toUpperCase()}
                  </Avatar>
                </ListItemAvatar>
                <ListItemText
                  primary={friend.username}
                  secondary={friend.first_name ? `${friend.first_name} ${friend.last_name || ''}`.trim() : undefined}
                />
              </ListItem>
            ))}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>
          Cancel
        </Button>
        <Button
          onClick={handleCreate}
          variant="contained"
          disabled={loading || !name.trim()}
          startIcon={loading ? <CircularProgress size={16} /> : <GroupIcon />}
        >
          Create Group
        </Button>
      </DialogActions>
    </Dialog>
  );
}
