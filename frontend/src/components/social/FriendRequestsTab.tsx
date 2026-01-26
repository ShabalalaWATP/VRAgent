import React, { useState } from 'react';
import {
  Box,
  Typography,
  Avatar,
  Button,
  IconButton,
  CircularProgress,
  Alert,
  Tooltip,
  Paper,
  Fade,
  alpha,
} from '@mui/material';
import {
  Check as AcceptIcon,
  Close as RejectIcon,
  Cancel as CancelIcon,
  Schedule as TimeIcon,
  Inbox as InboxIcon,
  Send as SentIcon,
  PersonAdd as PersonAddIcon,
} from '@mui/icons-material';
import { FriendRequestListResponse, FriendRequest, socialApi } from '../../api/client';

interface FriendRequestsTabProps {
  requests: FriendRequestListResponse | null;
  onRefresh: () => void;
}

export default function FriendRequestsTab({ requests, onRefresh }: FriendRequestsTabProps) {
  const [processing, setProcessing] = useState<number | null>(null);
  const [error, setError] = useState('');

  const handleAccept = async (requestId: number) => {
    setProcessing(requestId);
    setError('');
    try {
      await socialApi.respondToFriendRequest(requestId, true);
      onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to accept request');
    } finally {
      setProcessing(null);
    }
  };

  const handleReject = async (requestId: number) => {
    setProcessing(requestId);
    setError('');
    try {
      await socialApi.respondToFriendRequest(requestId, false);
      onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reject request');
    } finally {
      setProcessing(null);
    }
  };

  const handleCancel = async (requestId: number) => {
    setProcessing(requestId);
    setError('');
    try {
      await socialApi.cancelFriendRequest(requestId);
      onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to cancel request');
    } finally {
      setProcessing(null);
    }
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days}d ago`;
    return date.toLocaleDateString();
  };

  const renderIncomingRequest = (request: FriendRequest, index: number) => (
    <Fade in key={request.id} style={{ transitionDelay: `${index * 30}ms` }}>
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
            bgcolor: (theme) => alpha(theme.palette.success.main, 0.04),
          },
        }}
      >
        <Avatar
          sx={{
            width: 48,
            height: 48,
            bgcolor: 'primary.main',
            fontSize: '1.1rem',
            fontWeight: 600,
          }}
        >
          {request.sender_username.charAt(0).toUpperCase()}
        </Avatar>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle2" fontWeight={600} noWrap>
              {request.sender_username}
            </Typography>
            {(request.sender_first_name || request.sender_last_name) && (
              <Typography variant="body2" color="text.secondary" noWrap>
                {request.sender_first_name} {request.sender_last_name}
              </Typography>
            )}
          </Box>
          {request.message && (
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{
                fontStyle: 'italic',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
                mt: 0.25,
              }}
            >
              "{request.message}"
            </Typography>
          )}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5 }}>
            <TimeIcon sx={{ fontSize: 12, color: 'text.disabled' }} />
            <Typography variant="caption" color="text.secondary">
              {formatDate(request.created_at)}
            </Typography>
          </Box>
        </Box>

        <Box sx={{ display: 'flex', gap: 1 }}>
          <Tooltip title="Accept">
            <Button
              variant="contained"
              color="success"
              size="small"
              onClick={() => handleAccept(request.id)}
              disabled={processing === request.id}
              sx={{
                minWidth: 'auto',
                px: 1.5,
                borderRadius: 2,
                boxShadow: 'none',
                '&:hover': { boxShadow: 'none' },
              }}
            >
              {processing === request.id ? (
                <CircularProgress size={18} color="inherit" />
              ) : (
                <AcceptIcon fontSize="small" />
              )}
            </Button>
          </Tooltip>
          <Tooltip title="Decline">
            <IconButton
              size="small"
              onClick={() => handleReject(request.id)}
              disabled={processing === request.id}
              sx={{
                bgcolor: (theme) => alpha(theme.palette.error.main, 0.1),
                color: 'error.main',
                '&:hover': {
                  bgcolor: (theme) => alpha(theme.palette.error.main, 0.2),
                },
              }}
            >
              <RejectIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>
    </Fade>
  );

  const renderOutgoingRequest = (request: FriendRequest, index: number) => (
    <Fade in key={request.id} style={{ transitionDelay: `${index * 30}ms` }}>
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
            bgcolor: (theme) => alpha(theme.palette.action.hover, 0.5),
          },
        }}
      >
        <Avatar
          sx={{
            width: 48,
            height: 48,
            bgcolor: 'secondary.main',
            fontSize: '1.1rem',
            fontWeight: 600,
          }}
        >
          {request.receiver_username.charAt(0).toUpperCase()}
        </Avatar>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle2" fontWeight={600} noWrap>
              {request.receiver_username}
            </Typography>
            {(request.receiver_first_name || request.receiver_last_name) && (
              <Typography variant="body2" color="text.secondary" noWrap>
                {request.receiver_first_name} {request.receiver_last_name}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5 }}>
            <TimeIcon sx={{ fontSize: 12, color: 'text.disabled' }} />
            <Typography variant="caption" color="text.secondary">
              Sent {formatDate(request.created_at)}
            </Typography>
          </Box>
        </Box>

        <Tooltip title="Cancel Request">
          <IconButton
            size="small"
            onClick={() => handleCancel(request.id)}
            disabled={processing === request.id}
            sx={{
              bgcolor: (theme) => alpha(theme.palette.error.main, 0.1),
              color: 'error.main',
              '&:hover': {
                bgcolor: (theme) => alpha(theme.palette.error.main, 0.2),
              },
            }}
          >
            {processing === request.id ? (
              <CircularProgress size={18} color="inherit" />
            ) : (
              <CancelIcon fontSize="small" />
            )}
          </IconButton>
        </Tooltip>
      </Box>
    </Fade>
  );

  const hasIncoming = requests && requests.incoming.length > 0;
  const hasOutgoing = requests && requests.outgoing.length > 0;
  const isEmpty = !hasIncoming && !hasOutgoing;

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

      {isEmpty && (
        <Paper
          elevation={0}
          sx={{
            borderRadius: 3,
            bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
            border: '1px solid',
            borderColor: 'divider',
            p: 4,
            textAlign: 'center',
          }}
        >
          <PersonAddIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
          <Typography color="text.secondary">
            No pending requests
          </Typography>
          <Typography variant="caption" color="text.disabled">
            Contact requests you send or receive will appear here
          </Typography>
        </Paper>
      )}

      {/* Incoming Requests */}
      {hasIncoming && (
        <Paper
          elevation={0}
          sx={{
            borderRadius: 3,
            bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
            border: '1px solid',
            borderColor: 'divider',
            overflow: 'hidden',
            mb: hasOutgoing ? 2 : 0,
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              p: 2,
              borderBottom: '1px solid',
              borderColor: 'divider',
              bgcolor: (theme) => alpha(theme.palette.success.main, 0.05),
            }}
          >
            <Box
              sx={{
                p: 1,
                borderRadius: 2,
                bgcolor: (theme) => alpha(theme.palette.success.main, 0.1),
                display: 'flex',
              }}
            >
              <InboxIcon color="success" fontSize="small" />
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={600}>
                Incoming
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {requests!.incoming_count} request{requests!.incoming_count !== 1 ? 's' : ''} waiting
              </Typography>
            </Box>
          </Box>
          <Box sx={{ p: 1 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              {requests!.incoming.map((request, index) => renderIncomingRequest(request, index))}
            </Box>
          </Box>
        </Paper>
      )}

      {/* Outgoing Requests */}
      {hasOutgoing && (
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
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
              p: 2,
              borderBottom: '1px solid',
              borderColor: 'divider',
              bgcolor: (theme) => alpha(theme.palette.background.default, 0.5),
            }}
          >
            <Box
              sx={{
                p: 1,
                borderRadius: 2,
                bgcolor: (theme) => alpha(theme.palette.primary.main, 0.1),
                display: 'flex',
              }}
            >
              <SentIcon color="primary" fontSize="small" />
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={600}>
                Sent
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {requests!.outgoing_count} pending request{requests!.outgoing_count !== 1 ? 's' : ''}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ p: 1 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              {requests!.outgoing.map((request, index) => renderOutgoingRequest(request, index))}
            </Box>
          </Box>
        </Paper>
      )}
    </Box>
  );
}
