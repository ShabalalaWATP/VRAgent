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
  Typography,
  Box,
  CircularProgress,
  Alert,
  Divider,
  IconButton,
  Paper,
  Chip,
} from '@mui/material';
import {
  History as HistoryIcon,
  Close as CloseIcon,
  ArrowForward as ArrowIcon,
} from '@mui/icons-material';
import { socialApi, EditHistoryEntry } from '../../api/client';

interface EditHistoryDialogProps {
  open: boolean;
  onClose: () => void;
  messageId: number | null;
  currentContent: string;
}

export function EditHistoryDialog({
  open,
  onClose,
  messageId,
  currentContent,
}: EditHistoryDialogProps) {
  const [history, setHistory] = useState<EditHistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const loadHistory = useCallback(async () => {
    if (!messageId) return;
    
    setLoading(true);
    setError('');
    try {
      const result = await socialApi.getMessageEditHistory(messageId);
      setHistory(result.history);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load edit history');
    } finally {
      setLoading(false);
    }
  }, [messageId]);

  useEffect(() => {
    if (open && messageId) {
      loadHistory();
    } else {
      setHistory([]);
    }
  }, [open, messageId, loadHistory]);

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  };

  const getTimeDiff = (dateStr: string, prevDateStr?: string) => {
    const date = new Date(dateStr);
    const prevDate = prevDateStr ? new Date(prevDateStr) : null;
    
    if (!prevDate) return '';
    
    const diffMs = date.getTime() - prevDate.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffDays > 0) return `${diffDays}d later`;
    if (diffHours > 0) return `${diffHours}h later`;
    if (diffMins > 0) return `${diffMins}m later`;
    return 'moments later';
  };

  // Create display entries: history entries + current content
  const displayEntries = [
    ...history.map((h, index) => ({
      content: h.previous_content,
      editedAt: h.edited_at,
      editNumber: h.edit_number,
      isCurrent: false,
      timeDiff: index > 0 ? getTimeDiff(h.edited_at, history[index - 1].edited_at) : '',
    })),
    ...(history.length > 0 ? [{
      content: currentContent,
      editedAt: null as string | null,
      editNumber: history.length + 1,
      isCurrent: true,
      timeDiff: getTimeDiff(new Date().toISOString(), history[history.length - 1].edited_at),
    }] : []),
  ];

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box display="flex" alignItems="center" gap={1}>
          <HistoryIcon color="primary" />
          <Typography variant="h6">Edit History</Typography>
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
        ) : history.length === 0 ? (
          <Box textAlign="center" py={4}>
            <HistoryIcon sx={{ fontSize: 64, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" color="text.secondary">
              No edit history
            </Typography>
            <Typography variant="body2" color="text.secondary">
              This message has not been edited
            </Typography>
          </Box>
        ) : (
          <List>
            {displayEntries.map((entry, index) => (
              <React.Fragment key={index}>
                {index > 0 && (
                  <Box display="flex" alignItems="center" justifyContent="center" py={1}>
                    <ArrowIcon sx={{ color: 'text.secondary', transform: 'rotate(90deg)' }} />
                    {entry.timeDiff && (
                      <Typography variant="caption" color="text.secondary" ml={1}>
                        {entry.timeDiff}
                      </Typography>
                    )}
                  </Box>
                )}
                <ListItem
                  sx={{
                    flexDirection: 'column',
                    alignItems: 'stretch',
                    bgcolor: entry.isCurrent ? 'action.selected' : 'transparent',
                    borderRadius: 1,
                  }}
                >
                  <Box display="flex" alignItems="center" gap={1} mb={1}>
                    <Chip
                      label={entry.isCurrent ? 'Current' : `Version ${entry.editNumber}`}
                      size="small"
                      color={entry.isCurrent ? 'primary' : 'default'}
                      variant={entry.isCurrent ? 'filled' : 'outlined'}
                    />
                    {entry.editedAt && (
                      <Typography variant="caption" color="text.secondary">
                        {formatDate(entry.editedAt)}
                      </Typography>
                    )}
                    {entry.isCurrent && (
                      <Typography variant="caption" color="text.secondary">
                        (now)
                      </Typography>
                    )}
                  </Box>
                  <Paper
                    variant="outlined"
                    sx={{
                      p: 2,
                      bgcolor: entry.isCurrent ? 'background.paper' : 'action.hover',
                    }}
                  >
                    <Typography
                      variant="body2"
                      sx={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
                    >
                      {entry.content}
                    </Typography>
                  </Paper>
                </ListItem>
                {index < displayEntries.length - 1 && <Divider sx={{ my: 1 }} />}
              </React.Fragment>
            ))}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Typography variant="caption" color="text.secondary" sx={{ flex: 1, pl: 2 }}>
          {history.length} edit{history.length !== 1 ? 's' : ''}
        </Typography>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

export default EditHistoryDialog;
