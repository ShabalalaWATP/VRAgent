import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  TextField,
  Typography,
  Box,
  CircularProgress,
  Alert,
  Chip,
  Radio,
  Paper,
} from '@mui/material';
import {
  Group as GroupIcon,
  Share as ShareIcon,
  BugReport as BugIcon,
  Assessment as ReportIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { socialApi, ConversationSummary } from '../../api/client';
import { useAuth } from '../../contexts/AuthContext';

interface ShareToConversationDialogProps {
  open: boolean;
  onClose: () => void;
  shareType: 'finding' | 'report';
  itemId: number;
  itemTitle?: string;
  itemSeverity?: string;
  itemDetails?: {
    // For findings
    type?: string;
    filePath?: string;
    projectName?: string;
    // For reports
    riskScore?: number;
    findingCount?: number;
  };
  onShareSuccess?: (conversationId: number) => void;
}

export default function ShareToConversationDialog({
  open,
  onClose,
  shareType,
  itemId,
  itemTitle,
  itemSeverity,
  itemDetails,
  onShareSuccess,
}: ShareToConversationDialogProps) {
  const { user } = useAuth();
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<number | null>(null);
  const [comment, setComment] = useState('');
  const [loading, setLoading] = useState(true);
  const [sharing, setSharing] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    if (open) {
      loadConversations();
      setSelectedConversation(null);
      setComment('');
      setError('');
      setSuccess(false);
    }
  }, [open]);

  const loadConversations = async () => {
    setLoading(true);
    try {
      const result = await socialApi.getConversations();
      setConversations(result.conversations);
    } catch (err) {
      setError('Failed to load conversations');
    } finally {
      setLoading(false);
    }
  };

  const getConversationName = (conv: ConversationSummary) => {
    if (conv.name) return conv.name;
    if (!conv.is_group) {
      const other = conv.participants.find(p => p.user_id !== user?.id);
      return other?.username || 'Unknown';
    }
    return 'Group Chat';
  };

  const handleShare = async () => {
    if (!selectedConversation) return;

    setSharing(true);
    setError('');

    try {
      if (shareType === 'finding') {
        await socialApi.shareFinding({
          finding_id: itemId,
          conversation_id: selectedConversation,
          comment: comment.trim() || undefined,
        });
      } else {
        await socialApi.shareReport({
          report_id: itemId,
          conversation_id: selectedConversation,
          comment: comment.trim() || undefined,
        });
      }
      setSuccess(true);
      onShareSuccess?.(selectedConversation);
      setTimeout(() => {
        onClose();
      }, 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to share');
    } finally {
      setSharing(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'error';
      case 'high':
        return 'warning';
      case 'medium':
        return 'info';
      case 'low':
        return 'success';
      default:
        return 'default';
    }
  };

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <ShareIcon color="primary" />
        Share {shareType === 'finding' ? 'Finding' : 'Report'}
      </DialogTitle>
      <DialogContent>
        {/* Item Preview */}
        <Paper
          elevation={0}
          sx={{
            p: 2,
            mb: 2,
            bgcolor: 'action.hover',
            border: '1px solid',
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 2 }}>
            <Box
              sx={{
                p: 1,
                borderRadius: 1,
                bgcolor: shareType === 'finding' ? 'error.main' : 'primary.main',
                color: 'white',
              }}
            >
              {shareType === 'finding' ? <BugIcon /> : <ReportIcon />}
            </Box>
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                <Typography variant="subtitle1" fontWeight={500}>
                  {itemTitle || `${shareType === 'finding' ? 'Finding' : 'Report'} #${itemId}`}
                </Typography>
                {itemSeverity && (
                  <Chip
                    label={itemSeverity.toUpperCase()}
                    size="small"
                    color={getSeverityColor(itemSeverity) as any}
                  />
                )}
              </Box>
              {itemDetails?.projectName && (
                <Typography variant="body2" color="text.secondary">
                  Project: {itemDetails.projectName}
                </Typography>
              )}
              {itemDetails?.type && (
                <Typography variant="body2" color="text.secondary">
                  Type: {itemDetails.type}
                </Typography>
              )}
              {itemDetails?.filePath && (
                <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                  {itemDetails.filePath}
                </Typography>
              )}
              {itemDetails?.riskScore !== undefined && (
                <Typography variant="body2" color="text.secondary">
                  Risk Score: {itemDetails.riskScore.toFixed(0)}/100 • {itemDetails.findingCount} findings
                </Typography>
              )}
            </Box>
          </Box>
        </Paper>

        {/* Optional Comment */}
        <TextField
          fullWidth
          label="Add a comment (optional)"
          placeholder="Add context or notes about this share..."
          value={comment}
          onChange={(e) => setComment(e.target.value)}
          multiline
          rows={2}
          sx={{ mb: 2 }}
        />

        {/* Conversation Selection */}
        <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 1 }}>
          Select a conversation to share to:
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>
            {error}
          </Alert>
        )}

        {success && (
          <Alert severity="success" sx={{ mb: 2 }}>
            Successfully shared! Redirecting...
          </Alert>
        )}

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : conversations.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography color="text.secondary">
              No conversations available. Start chatting with contacts first!
            </Typography>
          </Box>
        ) : (
          <List sx={{ maxHeight: 300, overflow: 'auto' }}>
            {conversations.map((conv) => {
              const other = conv.participants.find(p => p.user_id !== user?.id);
              return (
                <ListItem
                  key={conv.id}
                  onClick={() => setSelectedConversation(conv.id)}
                  sx={{
                    border: '1px solid',
                    borderColor: selectedConversation === conv.id ? 'primary.main' : 'divider',
                    borderRadius: 1,
                    mb: 0.5,
                    cursor: 'pointer',
                    bgcolor: selectedConversation === conv.id ? 'action.selected' : 'transparent',
                    '&:hover': { bgcolor: 'action.hover' },
                  }}
                >
                  <Radio
                    checked={selectedConversation === conv.id}
                    size="small"
                    sx={{ mr: 1 }}
                  />
                  <ListItemAvatar>
                    {conv.is_group ? (
                      <Avatar sx={{ bgcolor: 'secondary.main' }}>
                        <GroupIcon />
                      </Avatar>
                    ) : (
                      <Avatar src={other?.avatar_url} sx={{ bgcolor: 'primary.main' }}>
                        {other?.username?.charAt(0).toUpperCase() || '?'}
                      </Avatar>
                    )}
                  </ListItemAvatar>
                  <ListItemText
                    primary={getConversationName(conv)}
                    secondary={
                      conv.is_group
                        ? `${conv.participant_count} members`
                        : other?.first_name ? `${other.first_name} ${other.last_name || ''}` : null
                    }
                  />
                </ListItem>
              );
            })}
          </List>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={sharing}>
          Cancel
        </Button>
        <Button
          variant="contained"
          onClick={handleShare}
          disabled={!selectedConversation || sharing || success}
          startIcon={sharing ? <CircularProgress size={16} /> : <ShareIcon />}
        >
          {sharing ? 'Sharing...' : 'Share'}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
