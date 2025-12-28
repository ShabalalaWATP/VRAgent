import React, { useState } from 'react';
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
  Divider,
  Tooltip,
  Card,
  CardContent,
} from '@mui/material';
import {
  Check as AcceptIcon,
  Close as RejectIcon,
  Cancel as CancelIcon,
  AccessTime as TimeIcon,
} from '@mui/icons-material';
import { socialApi, FriendRequestListResponse, FriendRequest } from '../../api/client';

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
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    
    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days} days ago`;
    return date.toLocaleDateString();
  };

  const renderIncomingRequest = (request: FriendRequest) => (
    <ListItem
      key={request.id}
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
        flexDirection: { xs: 'column', sm: 'row' },
        alignItems: { xs: 'flex-start', sm: 'center' },
      }}
    >
      <ListItemAvatar>
        <Avatar sx={{ bgcolor: 'primary.main' }}>
          {request.sender_username.charAt(0).toUpperCase()}
        </Avatar>
      </ListItemAvatar>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle1" fontWeight={500}>
              {request.sender_username}
            </Typography>
            {(request.sender_first_name || request.sender_last_name) && (
              <Typography variant="body2" color="text.secondary">
                ({request.sender_first_name} {request.sender_last_name})
              </Typography>
            )}
          </Box>
        }
        secondary={
          <>
            {request.message && (
              <Typography variant="body2" sx={{ fontStyle: 'italic', mb: 0.5 }}>
                "{request.message}"
              </Typography>
            )}
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <TimeIcon sx={{ fontSize: 14 }} />
              <Typography variant="caption" color="text.secondary">
                {formatDate(request.created_at)}
              </Typography>
            </Box>
          </>
        }
      />
      <Box sx={{ display: 'flex', gap: 1, mt: { xs: 1, sm: 0 } }}>
        <Tooltip title="Accept">
          <IconButton
            color="success"
            onClick={() => handleAccept(request.id)}
            disabled={processing === request.id}
          >
            {processing === request.id ? <CircularProgress size={20} /> : <AcceptIcon />}
          </IconButton>
        </Tooltip>
        <Tooltip title="Reject">
          <IconButton
            color="error"
            onClick={() => handleReject(request.id)}
            disabled={processing === request.id}
          >
            <RejectIcon />
          </IconButton>
        </Tooltip>
      </Box>
    </ListItem>
  );

  const renderOutgoingRequest = (request: FriendRequest) => (
    <ListItem
      key={request.id}
      sx={{
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
        mb: 1,
      }}
    >
      <ListItemAvatar>
        <Avatar sx={{ bgcolor: 'secondary.main' }}>
          {request.receiver_username.charAt(0).toUpperCase()}
        </Avatar>
      </ListItemAvatar>
      <ListItemText
        primary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Typography variant="subtitle1" fontWeight={500}>
              {request.receiver_username}
            </Typography>
            {(request.receiver_first_name || request.receiver_last_name) && (
              <Typography variant="body2" color="text.secondary">
                ({request.receiver_first_name} {request.receiver_last_name})
              </Typography>
            )}
          </Box>
        }
        secondary={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <TimeIcon sx={{ fontSize: 14 }} />
            <Typography variant="caption" color="text.secondary">
              Sent {formatDate(request.created_at)}
            </Typography>
          </Box>
        }
      />
      <Tooltip title="Cancel Request">
        <IconButton
          color="error"
          onClick={() => handleCancel(request.id)}
          disabled={processing === request.id}
        >
          {processing === request.id ? <CircularProgress size={20} /> : <CancelIcon />}
        </IconButton>
      </Tooltip>
    </ListItem>
  );

  const hasIncoming = requests && requests.incoming.length > 0;
  const hasOutgoing = requests && requests.outgoing.length > 0;
  const isEmpty = !hasIncoming && !hasOutgoing;

  return (
    <Box sx={{ px: 3 }}>
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {isEmpty && (
        <Box sx={{ textAlign: 'center', py: 4 }}>
          <Typography color="text.secondary">
            No pending friend requests
          </Typography>
        </Box>
      )}

      {hasIncoming && (
        <Box sx={{ mb: 4 }}>
          <Typography variant="h6" gutterBottom>
            Incoming Requests ({requests!.incoming_count})
          </Typography>
          <List>
            {requests!.incoming.map(renderIncomingRequest)}
          </List>
        </Box>
      )}

      {hasIncoming && hasOutgoing && <Divider sx={{ my: 3 }} />}

      {hasOutgoing && (
        <Box>
          <Typography variant="h6" gutterBottom>
            Sent Requests ({requests!.outgoing_count})
          </Typography>
          <List>
            {requests!.outgoing.map(renderOutgoingRequest)}
          </List>
        </Box>
      )}
    </Box>
  );
}
