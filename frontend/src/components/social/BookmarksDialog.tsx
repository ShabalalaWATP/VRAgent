import React, { useState, useEffect, useCallback } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemText,
  ListItemAvatar,
  ListItemSecondaryAction,
  Avatar,
  IconButton,
  Typography,
  Box,
  TextField,
  CircularProgress,
  Alert,
  Chip,
  Divider,
  Tooltip,
  Paper,
} from '@mui/material';
import {
  Bookmark as BookmarkIcon,
  BookmarkBorder as BookmarkOutlineIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  OpenInNew as OpenIcon,
  Close as CloseIcon,
  Save as SaveIcon,
} from '@mui/icons-material';
import { socialApi, BookmarkResponse } from '../../api/client';

interface BookmarksDialogProps {
  open: boolean;
  onClose: () => void;
  onNavigateToMessage?: (conversationId: number, messageId: number) => void;
}

export function BookmarksDialog({ open, onClose, onNavigateToMessage }: BookmarksDialogProps) {
  const [bookmarks, setBookmarks] = useState<BookmarkResponse[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editNote, setEditNote] = useState('');

  const loadBookmarks = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await socialApi.getBookmarks();
      setBookmarks(result.bookmarks);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load bookmarks');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      loadBookmarks();
    }
  }, [open, loadBookmarks]);

  const handleRemoveBookmark = async (messageId: number) => {
    try {
      await socialApi.removeBookmark(messageId);
      setBookmarks(prev => prev.filter(b => b.message_id !== messageId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove bookmark');
    }
  };

  const handleEditNote = (bookmark: BookmarkResponse) => {
    setEditingId(bookmark.id);
    setEditNote(bookmark.note || '');
  };

  const handleSaveNote = async (bookmarkId: number) => {
    try {
      const updated = await socialApi.updateBookmark(bookmarkId, editNote || undefined);
      setBookmarks(prev => prev.map(b => b.id === bookmarkId ? updated : b));
      setEditingId(null);
      setEditNote('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update note');
    }
  };

  const handleNavigate = (bookmark: BookmarkResponse) => {
    onNavigateToMessage?.(bookmark.conversation_id, bookmark.message_id);
    onClose();
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <BookmarkIcon color="primary" />
          <Typography variant="h6">Bookmarked Messages</Typography>
          <Box flex={1} />
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Box>
      </DialogTitle>
      <DialogContent dividers>
        {loading ? (
          <Box display="flex" justifyContent="center" py={4}>
            <CircularProgress />
          </Box>
        ) : error ? (
          <Alert severity="error">{error}</Alert>
        ) : bookmarks.length === 0 ? (
          <Box textAlign="center" py={4}>
            <BookmarkOutlineIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              No bookmarks yet
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Bookmark messages to save them for later
            </Typography>
          </Box>
        ) : (
          <List>
            {bookmarks.map((bookmark, index) => (
              <React.Fragment key={bookmark.id}>
                {index > 0 && <Divider />}
                <ListItem alignItems="flex-start" sx={{ py: 2 }}>
                  <ListItemAvatar>
                    <Avatar src={bookmark.message_sender_avatar_url}>
                      {bookmark.message_sender_username[0]?.toUpperCase()}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box display="flex" alignItems="center" gap={1}>
                        <Typography variant="subtitle2">
                          {bookmark.message_sender_username}
                        </Typography>
                        {bookmark.conversation_name && (
                          <Chip
                            label={bookmark.conversation_name}
                            size="small"
                            variant="outlined"
                            sx={{ height: 20 }}
                          />
                        )}
                        <Typography variant="caption" color="text.secondary">
                          {formatDate(bookmark.message_created_at)}
                        </Typography>
                      </Box>
                    }
                    secondary={
                      <Box>
                        <Paper
                          variant="outlined"
                          sx={{ p: 1, mt: 1, bgcolor: 'action.hover' }}
                        >
                          <Typography
                            variant="body2"
                            sx={{
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              display: '-webkit-box',
                              WebkitLineClamp: 3,
                              WebkitBoxOrient: 'vertical',
                            }}
                          >
                            {bookmark.message_content}
                          </Typography>
                        </Paper>
                        
                        {editingId === bookmark.id ? (
                          <Box mt={1} display="flex" gap={1}>
                            <TextField
                              fullWidth
                              size="small"
                              value={editNote}
                              onChange={(e) => setEditNote(e.target.value)}
                              placeholder="Add a note..."
                              autoFocus
                            />
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => handleSaveNote(bookmark.id)}
                            >
                              <SaveIcon />
                            </IconButton>
                            <IconButton
                              size="small"
                              onClick={() => setEditingId(null)}
                            >
                              <CloseIcon />
                            </IconButton>
                          </Box>
                        ) : bookmark.note ? (
                          <Box mt={1} display="flex" alignItems="center" gap={1}>
                            <Typography variant="caption" color="text.secondary">
                              Note: {bookmark.note}
                            </Typography>
                          </Box>
                        ) : null}
                        
                        <Typography variant="caption" color="text.secondary" display="block" mt={0.5}>
                          Bookmarked {formatDate(bookmark.created_at)}
                        </Typography>
                      </Box>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Box display="flex" flexDirection="column" gap={0.5}>
                      <Tooltip title="Go to message">
                        <IconButton
                          size="small"
                          onClick={() => handleNavigate(bookmark)}
                        >
                          <OpenIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Edit note">
                        <IconButton
                          size="small"
                          onClick={() => handleEditNote(bookmark)}
                        >
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Remove bookmark">
                        <IconButton
                          size="small"
                          onClick={() => handleRemoveBookmark(bookmark.message_id)}
                        >
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </ListItemSecondaryAction>
                </ListItem>
              </React.Fragment>
            ))}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Typography variant="caption" color="text.secondary" sx={{ flex: 1, pl: 2 }}>
          {bookmarks.length} bookmark{bookmarks.length !== 1 ? 's' : ''}
        </Typography>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

export default BookmarksDialog;
