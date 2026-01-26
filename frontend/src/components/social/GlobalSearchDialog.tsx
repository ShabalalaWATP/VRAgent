import React, { useState, useCallback, useRef } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  Box,
  TextField,
  InputAdornment,
  Typography,
  Avatar,
  CircularProgress,
  List,
  ListItemButton,
  ListItemAvatar,
  ListItemText,
  Chip,
  IconButton,
  alpha,
  Fade,
  Divider,
} from '@mui/material';
import {
  Search as SearchIcon,
  Close as CloseIcon,
  Message as MessageIcon,
  Schedule as TimeIcon,
} from '@mui/icons-material';
import { socialApi, MessageSearchResult } from '../../api/client';

interface GlobalSearchDialogProps {
  open: boolean;
  onClose: () => void;
  onResultClick: (conversationId: number, messageId: number) => void;
}

export function GlobalSearchDialog({
  open,
  onClose,
  onResultClick,
}: GlobalSearchDialogProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<MessageSearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleSearch = useCallback(async (searchQuery: string) => {
    if (!searchQuery.trim()) {
      setResults([]);
      setSearched(false);
      return;
    }

    setLoading(true);
    setSearched(true);

    try {
      // Pass undefined for conversationId to search globally
      const response = await socialApi.searchMessages(searchQuery.trim(), undefined, 0, 100);
      setResults(response.results || []);
    } catch (err) {
      console.error('Global search failed:', err);
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleQueryChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setQuery(value);

    // Debounce search
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current);
    }

    searchTimeoutRef.current = setTimeout(() => {
      handleSearch(value);
    }, 300);
  };

  const handleResultClick = (result: MessageSearchResult) => {
    onResultClick(result.conversation_id, result.message_id);
    onClose();
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (days === 0) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
  };

  const handleClose = () => {
    setQuery('');
    setResults([]);
    setSearched(false);
    onClose();
  };

  // Group results by conversation
  const groupedResults = results.reduce((acc, result) => {
    const key = result.conversation_id;
    if (!acc[key]) {
      acc[key] = {
        conversation_id: result.conversation_id,
        conversation_name: result.conversation_name || 'Conversation',
        messages: [],
      };
    }
    acc[key].messages.push(result);
    return acc;
  }, {} as Record<number, { conversation_id: number; conversation_name: string; messages: MessageSearchResult[] }>);

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      PaperProps={{
        sx: {
          borderRadius: 3,
          maxHeight: '80vh',
        },
      }}
    >
      <DialogTitle sx={{ pb: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            <Box
              sx={{
                p: 1,
                borderRadius: 2,
                bgcolor: (theme) => alpha(theme.palette.primary.main, 0.1),
                display: 'flex',
              }}
            >
              <SearchIcon color="primary" />
            </Box>
            <Box>
              <Typography variant="h6" fontWeight={600}>
                Search All Messages
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Search across all your conversations
              </Typography>
            </Box>
          </Box>
          <IconButton onClick={handleClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>

      <DialogContent sx={{ p: 0 }}>
        {/* Search Input */}
        <Box sx={{ px: 3, pb: 2 }}>
          <TextField
            fullWidth
            autoFocus
            placeholder="Search messages, files, links..."
            value={query}
            onChange={handleQueryChange}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon color="action" />
                </InputAdornment>
              ),
              endAdornment: loading ? (
                <InputAdornment position="end">
                  <CircularProgress size={20} />
                </InputAdornment>
              ) : query ? (
                <InputAdornment position="end">
                  <IconButton size="small" onClick={() => { setQuery(''); setResults([]); setSearched(false); }}>
                    <CloseIcon fontSize="small" />
                  </IconButton>
                </InputAdornment>
              ) : null,
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                borderRadius: 2,
              },
            }}
          />
        </Box>

        <Divider />

        {/* Results */}
        <Box sx={{ maxHeight: 'calc(80vh - 180px)', overflow: 'auto' }}>
          {!searched ? (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <MessageIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
              <Typography color="text.secondary">
                Start typing to search
              </Typography>
              <Typography variant="caption" color="text.disabled">
                Search for keywords, usernames, or content
              </Typography>
            </Box>
          ) : loading ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 6 }}>
              <CircularProgress />
            </Box>
          ) : results.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <SearchIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
              <Typography color="text.secondary">
                No messages found for "{query}"
              </Typography>
            </Box>
          ) : (
            <List sx={{ py: 0 }}>
              {Object.values(groupedResults).map((group) => (
                <Box key={group.conversation_id}>
                  {/* Conversation Header */}
                  <Box
                    sx={{
                      px: 2,
                      py: 1,
                      bgcolor: (theme) => alpha(theme.palette.background.default, 0.5),
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      position: 'sticky',
                      top: 0,
                      zIndex: 1,
                    }}
                  >
                    <Avatar sx={{ width: 24, height: 24, bgcolor: 'primary.main', fontSize: 12 }}>
                      {group.conversation_name.charAt(0).toUpperCase()}
                    </Avatar>
                    <Typography variant="subtitle2" fontWeight={600}>
                      {group.conversation_name}
                    </Typography>
                    <Chip
                      label={`${group.messages.length} match${group.messages.length !== 1 ? 'es' : ''}`}
                      size="small"
                      sx={{ height: 20, fontSize: '0.7rem' }}
                    />
                  </Box>

                  {/* Messages in this conversation */}
                  {group.messages.map((result, index) => (
                    <Fade in key={result.message_id} style={{ transitionDelay: `${index * 20}ms` }}>
                      <ListItemButton
                        onClick={() => handleResultClick(result)}
                        sx={{
                          py: 1.5,
                          px: 2,
                          '&:hover': {
                            bgcolor: (theme) => alpha(theme.palette.primary.main, 0.04),
                          },
                        }}
                      >
                        <ListItemAvatar>
                          <Avatar sx={{ width: 36, height: 36, bgcolor: 'primary.main' }}>
                            {result.sender_username.charAt(0).toUpperCase()}
                          </Avatar>
                        </ListItemAvatar>
                        <ListItemText
                          primary={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="body2" fontWeight={500}>
                                {result.sender_username}
                              </Typography>
                              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                                <TimeIcon sx={{ fontSize: 12, color: 'text.disabled' }} />
                                <Typography variant="caption" color="text.secondary">
                                  {formatDate(result.created_at)}
                                </Typography>
                              </Box>
                            </Box>
                          }
                          secondary={
                            <Typography
                              variant="body2"
                              color="text.secondary"
                              sx={{
                                display: '-webkit-box',
                                WebkitLineClamp: 2,
                                WebkitBoxOrient: 'vertical',
                                overflow: 'hidden',
                                '& mark': {
                                  bgcolor: 'warning.light',
                                  color: 'warning.contrastText',
                                  px: 0.25,
                                  borderRadius: 0.5,
                                },
                              }}
                              dangerouslySetInnerHTML={{ __html: result.highlighted_content }}
                            />
                          }
                        />
                      </ListItemButton>
                    </Fade>
                  ))}
                </Box>
              ))}
            </List>
          )}
        </Box>
      </DialogContent>
    </Dialog>
  );
}

export default GlobalSearchDialog;
