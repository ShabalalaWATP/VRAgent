import React, { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Tabs,
  Tab,
  Badge,
  CircularProgress,
  Alert,
  Fade,
  alpha,
  Skeleton,
} from '@mui/material';
import {
  People as PeopleIcon,
  PersonSearch as SearchIcon,
  PersonAdd as RequestsIcon,
  Message as MessagesIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import {
  UserSearchTab,
  FriendRequestsTab,
  FriendsListTab,
  MessagesTab,
  StatusSelector,
} from '../components/social';
import type { PresenceStatus } from '../components/social';
import { socialApi, FriendRequestListResponse, UnreadCountResponse } from '../api/client';

// Polling intervals (in ms) - increased to reduce server load since WebSocket handles real-time
const POLLING_INTERVAL_VISIBLE = 60000; // 60 seconds when tab is visible
const POLLING_INTERVAL_HIDDEN = 120000; // 2 minutes when tab is hidden

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <Fade in={value === index} timeout={300}>
      <div
        role="tabpanel"
        hidden={value !== index}
        id={`social-tabpanel-${index}`}
        aria-labelledby={`social-tab-${index}`}
        {...other}
      >
        {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
      </div>
    </Fade>
  );
}

export default function SocialPage() {
  const { user } = useAuth();
  const [tabValue, setTabValue] = useState(0);
  const [friendRequests, setFriendRequests] = useState<FriendRequestListResponse | null>(null);
  const [unreadCounts, setUnreadCounts] = useState<UnreadCountResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Presence state
  const [myPresence, setMyPresence] = useState<{
    status: PresenceStatus;
    custom_status?: string;
    status_emoji?: string;
  }>({ status: 'online' });

  const loadCounts = useCallback(async () => {
    try {
      const [requestsData, unreadData] = await Promise.all([
        socialApi.getFriendRequests(),
        socialApi.getUnreadCounts(),
      ]);
      setFriendRequests(requestsData);
      setUnreadCounts(unreadData);
      setError('');
    } catch (err) {
      console.error('Failed to load social counts:', err);
      setError('Failed to load social data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCounts();
    loadMyPresence();

    // Track polling interval ref for dynamic adjustment
    let intervalId: ReturnType<typeof setInterval> | null = null;

    const startPolling = () => {
      // Use longer interval when tab is hidden to save resources
      const interval = document.hidden ? POLLING_INTERVAL_HIDDEN : POLLING_INTERVAL_VISIBLE;
      if (intervalId) clearInterval(intervalId);
      intervalId = setInterval(loadCounts, interval);
    };

    const handleVisibilityChange = () => {
      // Refresh immediately when tab becomes visible
      if (!document.hidden) {
        loadCounts();
      }
      // Adjust polling interval based on visibility
      startPolling();
    };

    // Start initial polling
    startPolling();

    // Listen for visibility changes to optimize polling
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      if (intervalId) clearInterval(intervalId);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [loadCounts]);

  const loadMyPresence = async () => {
    try {
      const response = await fetch('/api/social/presence/me', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`,
        },
      });
      if (response.ok) {
        const data = await response.json();
        setMyPresence({
          status: data.status || 'online',
          custom_status: data.custom_status,
          status_emoji: data.status_emoji,
        });
      }
    } catch (err) {
      console.error('Failed to load presence:', err);
    }
  };

  const handleStatusChange = async (
    status: PresenceStatus,
    customStatus?: string,
    statusEmoji?: string,
    durationMinutes?: number
  ) => {
    try {
      const response = await fetch('/api/social/presence/me', {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('vragent_access_token')}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          status,
          custom_status: customStatus,
          status_emoji: statusEmoji,
          duration_minutes: durationMinutes,
        }),
      });
      if (response.ok) {
        setMyPresence({ status, custom_status: customStatus, status_emoji: statusEmoji });
      }
    } catch (err) {
      console.error('Failed to update presence:', err);
    }
  };

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const refreshCounts = () => {
    loadCounts();
  };

  if (!user) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="warning" sx={{ borderRadius: 2 }}>
          Please log in to access social features.
        </Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      {/* Header */}
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          mb: 3,
        }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 700, letterSpacing: -0.5 }}>
            Social Hub
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Connect and collaborate with your team
          </Typography>
        </Box>
        <StatusSelector
          currentStatus={myPresence.status}
          customStatus={myPresence.custom_status}
          statusEmoji={myPresence.status_emoji}
          onStatusChange={handleStatusChange}
        />
      </Box>

      {/* Main Content */}
      <Paper
        elevation={0}
        sx={{
          borderRadius: 3,
          border: '1px solid',
          borderColor: 'divider',
          overflow: 'hidden',
          bgcolor: (theme) => alpha(theme.palette.background.paper, 0.8),
        }}
      >
        {/* Tabs */}
        <Box
          sx={{
            borderBottom: '1px solid',
            borderColor: 'divider',
            bgcolor: (theme) => alpha(theme.palette.background.default, 0.5),
          }}
        >
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            variant="fullWidth"
            TabIndicatorProps={{
              sx: {
                height: 3,
                borderRadius: '3px 3px 0 0',
              },
            }}
            sx={{
              '& .MuiTab-root': {
                minHeight: 56,
                textTransform: 'none',
                fontWeight: 500,
                fontSize: '0.9rem',
                color: 'text.secondary',
                transition: 'all 0.2s',
                '&:hover': {
                  color: 'text.primary',
                  bgcolor: (theme) => alpha(theme.palette.action.hover, 0.5),
                },
                '&.Mui-selected': {
                  color: 'primary.main',
                  fontWeight: 600,
                },
              },
            }}
          >
            <Tab
              icon={<SearchIcon sx={{ fontSize: 20 }} />}
              label="Find Users"
              iconPosition="start"
              sx={{ gap: 1 }}
            />
            <Tab
              icon={
                <Badge
                  badgeContent={friendRequests?.incoming_count || 0}
                  color="error"
                  max={99}
                  sx={{
                    '& .MuiBadge-badge': {
                      fontSize: '0.7rem',
                      minWidth: 18,
                      height: 18,
                    },
                  }}
                >
                  <RequestsIcon sx={{ fontSize: 20 }} />
                </Badge>
              }
              label="Requests"
              iconPosition="start"
              sx={{ gap: 1 }}
            />
            <Tab
              icon={<PeopleIcon sx={{ fontSize: 20 }} />}
              label="Contacts"
              iconPosition="start"
              sx={{ gap: 1 }}
            />
            <Tab
              icon={
                <Badge
                  badgeContent={unreadCounts?.total_unread || 0}
                  color="primary"
                  max={99}
                  sx={{
                    '& .MuiBadge-badge': {
                      fontSize: '0.7rem',
                      minWidth: 18,
                      height: 18,
                    },
                  }}
                >
                  <MessagesIcon sx={{ fontSize: 20 }} />
                </Badge>
              }
              label="Messages"
              iconPosition="start"
              sx={{ gap: 1 }}
            />
          </Tabs>
        </Box>

        {/* Tab Content */}
        {loading ? (
          <Box sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {Array.from({ length: 4 }).map((_, i) => (
                <Box key={i} sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                  <Skeleton variant="circular" width={48} height={48} />
                  <Box sx={{ flex: 1 }}>
                    <Skeleton variant="text" width="40%" height={24} />
                    <Skeleton variant="text" width="60%" height={20} />
                  </Box>
                </Box>
              ))}
            </Box>
          </Box>
        ) : (
          <>
            {error && (
              <Fade in>
                <Alert severity="error" sx={{ m: 2, borderRadius: 2 }}>
                  {error}
                </Alert>
              </Fade>
            )}

            <TabPanel value={tabValue} index={0}>
              <UserSearchTab onRequestSent={refreshCounts} />
            </TabPanel>

            <TabPanel value={tabValue} index={1}>
              <FriendRequestsTab
                requests={friendRequests}
                onRefresh={refreshCounts}
              />
            </TabPanel>

            <TabPanel value={tabValue} index={2}>
              <FriendsListTab onStartChat={() => setTabValue(3)} />
            </TabPanel>

            <TabPanel value={tabValue} index={3}>
              <MessagesTab
                unreadCounts={unreadCounts}
                onRefresh={refreshCounts}
              />
            </TabPanel>
          </>
        )}
      </Paper>
    </Container>
  );
}
