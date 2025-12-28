import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  InputAdornment,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  Button,
  Typography,
  CircularProgress,
  Alert,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Divider,
  Paper,
} from '@mui/material';
import {
  Search as SearchIcon,
  PersonAdd as PersonAddIcon,
  Check as CheckIcon,
  Schedule as PendingIcon,
  Send as SendIcon,
  People as PeopleIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { socialApi, UserPublicProfile } from '../../api/client';

interface UserSearchTabProps {
  onRequestSent: () => void;
}

export default function UserSearchTab({ onRequestSent }: UserSearchTabProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [users, setUsers] = useState<UserPublicProfile[]>([]);
  const [suggestedUsers, setSuggestedUsers] = useState<UserPublicProfile[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingSuggested, setLoadingSuggested] = useState(true);
  const [error, setError] = useState('');
  const [searched, setSearched] = useState(false);
  const [sendingTo, setSendingTo] = useState<number | null>(null);
  
  // Message dialog state
  const [messageDialogOpen, setMessageDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserPublicProfile | null>(null);
  const [requestMessage, setRequestMessage] = useState('');

  // Load suggested users on mount
  useEffect(() => {
    loadSuggestedUsers();
  }, []);

  const loadSuggestedUsers = async () => {
    setLoadingSuggested(true);
    try {
      const result = await socialApi.getSuggestedUsers(0, 50);
      setSuggestedUsers(result.users);
    } catch (err) {
      console.error('Failed to load suggested users:', err);
    } finally {
      setLoadingSuggested(false);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) {
      setSearched(false);
      setUsers([]);
      return;
    }

    setLoading(true);
    setError('');
    setSearched(true);

    try {
      const result = await socialApi.searchUsers(searchQuery.trim());
      setUsers(result.users);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed');
      setUsers([]);
    } finally {
      setLoading(false);
    }
  };

  const handleClearSearch = () => {
    setSearchQuery('');
    setSearched(false);
    setUsers([]);
  };

  const openSendRequest = (user: UserPublicProfile) => {
    setSelectedUser(user);
    setRequestMessage('');
    setMessageDialogOpen(true);
  };

  const handleSendRequest = async () => {
    if (!selectedUser) return;

    setSendingTo(selectedUser.id);
    setMessageDialogOpen(false);

    try {
      await socialApi.sendFriendRequest(selectedUser.id, requestMessage || undefined);
      // Update local state for both lists
      const updateUser = (u: UserPublicProfile) =>
        u.id === selectedUser.id
          ? { ...u, has_pending_request: true, request_direction: 'sent' as const }
          : u;
      setUsers(users.map(updateUser));
      setSuggestedUsers(suggestedUsers.map(updateUser));
      onRequestSent();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send request');
    } finally {
      setSendingTo(null);
      setSelectedUser(null);
    }
  };

  const getStatusButton = (user: UserPublicProfile) => {
    if (user.is_friend) {
      return (
        <Chip
          icon={<CheckIcon />}
          label="Friends"
          color="success"
          size="small"
          variant="outlined"
        />
      );
    }

    if (user.has_pending_request) {
      return (
        <Chip
          icon={<PendingIcon />}
          label={user.request_direction === 'sent' ? 'Request Sent' : 'Request Received'}
          color="warning"
          size="small"
          variant="outlined"
        />
      );
    }

    return (
      <Button
        variant="outlined"
        size="small"
        startIcon={sendingTo === user.id ? <CircularProgress size={16} /> : <PersonAddIcon />}
        onClick={() => openSendRequest(user)}
        disabled={sendingTo === user.id}
      >
        Add Friend
      </Button>
    );
  };

  const renderUserList = (userList: UserPublicProfile[], emptyMessage: string) => {
    if (userList.length === 0) {
      return (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography color="text.secondary">{emptyMessage}</Typography>
        </Box>
      );
    }

    return (
      <List>
        {userList.map((user) => (
          <ListItem
            key={user.id}
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              borderRadius: 1,
              mb: 1,
            }}
            secondaryAction={getStatusButton(user)}
          >
            <ListItemAvatar>
              <Avatar
                src={user.avatar_url}
                sx={{ bgcolor: 'primary.main' }}
              >
                {user.username.charAt(0).toUpperCase()}
              </Avatar>
            </ListItemAvatar>
            <ListItemText
              primary={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Typography variant="subtitle1" fontWeight={500}>
                    {user.username}
                  </Typography>
                  {(user.first_name || user.last_name) && (
                    <Typography variant="body2" color="text.secondary">
                      ({user.first_name} {user.last_name})
                    </Typography>
                  )}
                </Box>
              }
              secondary={user.bio || 'No bio'}
            />
          </ListItem>
        ))}
      </List>
    );
  };

  return (
    <Box sx={{ px: 3 }}>
      {/* Search Bar */}
      <Box component="form" onSubmit={handleSearch} sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search by username or name..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                {searchQuery && (
                  <IconButton size="small" onClick={handleClearSearch}>
                    ×
                  </IconButton>
                )}
                <IconButton type="submit" disabled={loading}>
                  {loading ? <CircularProgress size={24} /> : <SearchIcon />}
                </IconButton>
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* Search Results */}
      {searched && (
        <Paper variant="outlined" sx={{ mb: 3, p: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Typography variant="h6">
              Search Results for "{searchQuery}"
            </Typography>
            <Button size="small" onClick={handleClearSearch}>
              Clear Search
            </Button>
          </Box>
          {loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            renderUserList(users, `No users found matching "${searchQuery}"`)
          )}
        </Paper>
      )}

      {/* Suggested Users - Always Show */}
      {!searched && (
        <Paper variant="outlined" sx={{ p: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <PeopleIcon color="primary" />
              <Typography variant="h6">
                Platform Users
              </Typography>
              <Chip label={suggestedUsers.length} size="small" color="primary" />
            </Box>
            <IconButton onClick={loadSuggestedUsers} disabled={loadingSuggested} size="small">
              <RefreshIcon />
            </IconButton>
          </Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Connect with other users on the platform
          </Typography>
          {loadingSuggested ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            renderUserList(suggestedUsers, 'No other users on the platform yet')
          )}
        </Paper>
      )}

      {/* Send Request Dialog */}
      <Dialog open={messageDialogOpen} onClose={() => setMessageDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Send Friend Request</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Send a friend request to {selectedUser?.username}
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            placeholder="Add a message (optional)..."
            value={requestMessage}
            onChange={(e) => setRequestMessage(e.target.value)}
            inputProps={{ maxLength: 500 }}
            helperText={`${requestMessage.length}/500`}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMessageDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSendRequest}
            startIcon={<SendIcon />}
          >
            Send Request
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
