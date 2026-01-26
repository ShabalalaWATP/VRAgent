import React, { useState, useEffect } from 'react';
import {
  Box,
  TextField,
  InputAdornment,
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
  Paper,
  Fade,
  Skeleton,
  alpha,
} from '@mui/material';
import {
  Search as SearchIcon,
  PersonAdd as PersonAddIcon,
  Check as CheckIcon,
  Schedule as PendingIcon,
  Send as SendIcon,
  People as PeopleIcon,
  Refresh as RefreshIcon,
  Close as CloseIcon,
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
          label="Contact"
          color="success"
          size="small"
          sx={{
            fontWeight: 500,
            '& .MuiChip-icon': { fontSize: 16 },
          }}
        />
      );
    }

    if (user.has_pending_request) {
      return (
        <Chip
          icon={<PendingIcon />}
          label={user.request_direction === 'sent' ? 'Pending' : 'Respond'}
          color="warning"
          size="small"
          sx={{
            fontWeight: 500,
            '& .MuiChip-icon': { fontSize: 16 },
          }}
        />
      );
    }

    return (
      <Button
        variant="contained"
        size="small"
        startIcon={sendingTo === user.id ? <CircularProgress size={14} color="inherit" /> : <PersonAddIcon />}
        onClick={() => openSendRequest(user)}
        disabled={sendingTo === user.id}
        sx={{
          borderRadius: 2,
          textTransform: 'none',
          fontWeight: 500,
          boxShadow: 'none',
          '&:hover': {
            boxShadow: 'none',
          },
        }}
      >
        Add
      </Button>
    );
  };

  const renderUserCard = (user: UserPublicProfile, index: number) => (
    <Fade in key={user.id} style={{ transitionDelay: `${index * 30}ms` }}>
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
            transform: 'translateX(4px)',
          },
        }}
      >
        <Avatar
          src={user.avatar_url}
          sx={{
            width: 48,
            height: 48,
            bgcolor: 'primary.main',
            fontSize: '1.1rem',
            fontWeight: 600,
          }}
        >
          {user.username.charAt(0).toUpperCase()}
        </Avatar>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle2" fontWeight={600} noWrap>
              {user.username}
            </Typography>
            {(user.first_name || user.last_name) && (
              <Typography variant="body2" color="text.secondary" noWrap>
                {user.first_name} {user.last_name}
              </Typography>
            )}
          </Box>
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {user.bio || 'No bio yet'}
          </Typography>
        </Box>

        {getStatusButton(user)}
      </Box>
    </Fade>
  );

  const renderSkeletons = (count: number) => (
    <>
      {Array.from({ length: count }).map((_, i) => (
        <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 2, p: 2 }}>
          <Skeleton variant="circular" width={48} height={48} />
          <Box sx={{ flex: 1 }}>
            <Skeleton variant="text" width="40%" height={24} />
            <Skeleton variant="text" width="60%" height={20} />
          </Box>
          <Skeleton variant="rounded" width={64} height={32} />
        </Box>
      ))}
    </>
  );

  const renderUserList = (userList: UserPublicProfile[], emptyMessage: string, isLoading: boolean) => {
    if (isLoading) {
      return renderSkeletons(5);
    }

    if (userList.length === 0) {
      return (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <PeopleIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
          <Typography color="text.secondary">{emptyMessage}</Typography>
        </Box>
      );
    }

    return (
      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
        {userList.map((user, index) => renderUserCard(user, index))}
      </Box>
    );
  };

  return (
    <Box sx={{ px: 3, py: 1 }}>
      {/* Search Bar */}
      <Box component="form" onSubmit={handleSearch} sx={{ mb: 3 }}>
        <TextField
          fullWidth
          placeholder="Search by username or name..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          variant="outlined"
          sx={{
            '& .MuiOutlinedInput-root': {
              borderRadius: 3,
              bgcolor: 'background.paper',
              '&:hover .MuiOutlinedInput-notchedOutline': {
                borderColor: 'primary.main',
              },
            },
          }}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon color="action" />
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                {searchQuery && (
                  <IconButton size="small" onClick={handleClearSearch} sx={{ mr: 0.5 }}>
                    <CloseIcon fontSize="small" />
                  </IconButton>
                )}
                <Button
                  type="submit"
                  variant="contained"
                  disabled={loading || !searchQuery.trim()}
                  sx={{
                    borderRadius: 2,
                    minWidth: 'auto',
                    px: 2,
                    boxShadow: 'none',
                    '&:hover': { boxShadow: 'none' },
                  }}
                >
                  {loading ? <CircularProgress size={20} color="inherit" /> : 'Search'}
                </Button>
              </InputAdornment>
            ),
          }}
        />
      </Box>

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

      {/* Search Results */}
      {searched && (
        <Fade in>
          <Paper
            elevation={0}
            sx={{
              mb: 3,
              p: 2,
              borderRadius: 3,
              bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
              border: '1px solid',
              borderColor: 'divider',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="subtitle1" fontWeight={600}>
                Results for "{searchQuery}"
              </Typography>
              <Button
                size="small"
                onClick={handleClearSearch}
                sx={{ textTransform: 'none' }}
              >
                Clear
              </Button>
            </Box>
            {renderUserList(users, `No users found matching "${searchQuery}"`, loading)}
          </Paper>
        </Fade>
      )}

      {/* Suggested Users */}
      {!searched && (
        <Paper
          elevation={0}
          sx={{
            p: 2,
            borderRadius: 3,
            bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
            border: '1px solid',
            borderColor: 'divider',
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
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
                  Platform Users
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {suggestedUsers.length} users available to connect
                </Typography>
              </Box>
            </Box>
            <IconButton
              onClick={loadSuggestedUsers}
              disabled={loadingSuggested}
              size="small"
              sx={{
                bgcolor: (theme) => alpha(theme.palette.action.hover, 0.5),
                '&:hover': {
                  bgcolor: (theme) => alpha(theme.palette.action.hover, 0.8),
                },
              }}
            >
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Box>
          {renderUserList(suggestedUsers, 'No other users on the platform yet', loadingSuggested)}
        </Paper>
      )}

      {/* Send Request Dialog */}
      <Dialog
        open={messageDialogOpen}
        onClose={() => setMessageDialogOpen(false)}
        maxWidth="sm"
        fullWidth
        PaperProps={{
          sx: {
            borderRadius: 3,
            p: 1,
          },
        }}
      >
        <DialogTitle sx={{ pb: 1 }}>
          <Typography variant="h6" fontWeight={600}>
            Send Contact Request
          </Typography>
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Send a contact request to <strong>{selectedUser?.username}</strong>
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
            sx={{
              '& .MuiOutlinedInput-root': {
                borderRadius: 2,
              },
            }}
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button
            onClick={() => setMessageDialogOpen(false)}
            sx={{ textTransform: 'none' }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleSendRequest}
            startIcon={<SendIcon />}
            sx={{
              textTransform: 'none',
              borderRadius: 2,
              boxShadow: 'none',
              '&:hover': { boxShadow: 'none' },
            }}
          >
            Send Request
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
