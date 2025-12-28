import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  IconButton,
  Chip,
  LinearProgress,
  Tooltip,
  Collapse,
  Alert,
  Button,
} from '@mui/material';
import {
  CloudOff as OfflineIcon,
  CloudQueue as OnlineIcon,
  Refresh as RetryIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  Schedule as PendingIcon,
  Error as ErrorIcon,
  Send as SendingIcon,
} from '@mui/icons-material';
import { QueuedMessage } from '../../hooks/useChatWebSocket';

interface OfflineQueueIndicatorProps {
  isOnline: boolean;
  queuedMessages: QueuedMessage[];
  conversationId?: number;
  onRetry: (id: string) => void;
  onRemove: (id: string) => void;
  onProcessQueue: () => void;
}

export function OfflineQueueIndicator({
  isOnline,
  queuedMessages,
  conversationId,
  onRetry,
  onRemove,
  onProcessQueue,
}: OfflineQueueIndicatorProps) {
  const [expanded, setExpanded] = useState(false);

  // Filter to current conversation if provided
  const relevantMessages = conversationId
    ? queuedMessages.filter(m => m.conversationId === conversationId)
    : queuedMessages;

  const pendingCount = relevantMessages.filter(m => m.status === 'pending').length;
  const sendingCount = relevantMessages.filter(m => m.status === 'sending').length;
  const failedCount = relevantMessages.filter(m => m.status === 'failed').length;

  if (isOnline && relevantMessages.length === 0) {
    return null;
  }

  const getStatusIcon = (status: QueuedMessage['status']) => {
    switch (status) {
      case 'pending':
        return <PendingIcon fontSize="small" color="warning" />;
      case 'sending':
        return <SendingIcon fontSize="small" color="info" />;
      case 'failed':
        return <ErrorIcon fontSize="small" color="error" />;
      default:
        return null;
    }
  };

  const getStatusText = (status: QueuedMessage['status']) => {
    switch (status) {
      case 'pending':
        return 'Pending';
      case 'sending':
        return 'Sending...';
      case 'failed':
        return 'Failed';
      default:
        return '';
    }
  };

  const formatTime = (timestamp: number) => {
    return new Date(timestamp).toLocaleTimeString(undefined, {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <Paper
      elevation={2}
      sx={{
        position: 'sticky',
        top: 0,
        zIndex: 10,
        borderRadius: 0,
        borderBottom: 1,
        borderColor: 'divider',
      }}
    >
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1,
          p: 1,
          bgcolor: isOnline ? 'background.paper' : 'warning.main',
          color: isOnline ? 'text.primary' : 'warning.contrastText',
          cursor: 'pointer',
        }}
        onClick={() => setExpanded(!expanded)}
      >
        {isOnline ? (
          <OnlineIcon fontSize="small" color="success" />
        ) : (
          <OfflineIcon fontSize="small" />
        )}
        
        <Typography variant="body2" sx={{ flex: 1 }}>
          {isOnline ? 'Online' : 'Offline - Messages will be queued'}
        </Typography>

        {pendingCount > 0 && (
          <Chip
            size="small"
            icon={<PendingIcon />}
            label={`${pendingCount} pending`}
            color="warning"
            variant="outlined"
          />
        )}
        
        {sendingCount > 0 && (
          <Chip
            size="small"
            icon={<SendingIcon />}
            label={`${sendingCount} sending`}
            color="info"
            variant="outlined"
          />
        )}
        
        {failedCount > 0 && (
          <Chip
            size="small"
            icon={<ErrorIcon />}
            label={`${failedCount} failed`}
            color="error"
            variant="outlined"
          />
        )}

        {relevantMessages.length > 0 && (
          <IconButton size="small" sx={{ color: 'inherit' }}>
            {expanded ? <CollapseIcon /> : <ExpandIcon />}
          </IconButton>
        )}
      </Box>

      {sendingCount > 0 && <LinearProgress />}

      <Collapse in={expanded && relevantMessages.length > 0}>
        <Box sx={{ maxHeight: 200, overflow: 'auto', p: 1 }}>
          {isOnline && failedCount > 0 && (
            <Box mb={1}>
              <Button
                size="small"
                variant="outlined"
                startIcon={<RetryIcon />}
                onClick={(e) => {
                  e.stopPropagation();
                  onProcessQueue();
                }}
              >
                Retry All Failed
              </Button>
            </Box>
          )}
          
          {relevantMessages.map((msg) => (
            <Paper
              key={msg.id}
              variant="outlined"
              sx={{
                p: 1,
                mb: 1,
                bgcolor: msg.status === 'failed' ? 'error.light' : 'action.hover',
              }}
            >
              <Box display="flex" alignItems="flex-start" gap={1}>
                {getStatusIcon(msg.status)}
                <Box flex={1} minWidth={0}>
                  <Typography
                    variant="body2"
                    sx={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {msg.content || `[${msg.messageType}]`}
                  </Typography>
                  <Box display="flex" alignItems="center" gap={1} mt={0.5}>
                    <Typography variant="caption" color="text.secondary">
                      {formatTime(msg.timestamp)}
                    </Typography>
                    <Chip
                      label={getStatusText(msg.status)}
                      size="small"
                      sx={{ height: 18, fontSize: '0.7rem' }}
                    />
                    {msg.status === 'failed' && msg.retryCount > 0 && (
                      <Typography variant="caption" color="error">
                        Retries: {msg.retryCount}/3
                      </Typography>
                    )}
                  </Box>
                </Box>
                <Box display="flex" gap={0.5}>
                  {msg.status === 'failed' && isOnline && (
                    <Tooltip title="Retry">
                      <IconButton
                        size="small"
                        onClick={(e) => {
                          e.stopPropagation();
                          onRetry(msg.id);
                        }}
                      >
                        <RetryIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  )}
                  <Tooltip title="Remove">
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        onRemove(msg.id);
                      }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Box>
            </Paper>
          ))}
        </Box>
      </Collapse>
    </Paper>
  );
}

export default OfflineQueueIndicator;
