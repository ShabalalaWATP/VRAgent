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
} from '@mui/material';
import {
  People as PeopleIcon,
  PersonSearch as SearchIcon,
  PersonAdd as RequestsIcon,
  Message as MessagesIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import UserSearchTab from '../components/social/UserSearchTab';
import FriendRequestsTab from '../components/social/FriendRequestsTab';
import FriendsListTab from '../components/social/FriendsListTab';
import MessagesTab from '../components/social/MessagesTab';
import { socialApi, FriendRequestListResponse, UnreadCountResponse } from '../api/client';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`social-tabpanel-${index}`}
      aria-labelledby={`social-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

export default function SocialPage() {
  const { user } = useAuth();
  const [tabValue, setTabValue] = useState(0);
  const [friendRequests, setFriendRequests] = useState<FriendRequestListResponse | null>(null);
  const [unreadCounts, setUnreadCounts] = useState<UnreadCountResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

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
    // Refresh counts every 30 seconds
    const interval = setInterval(loadCounts, 30000);
    return () => clearInterval(interval);
  }, [loadCounts]);

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const refreshCounts = () => {
    loadCounts();
  };

  if (!user) {
    return (
      <Container maxWidth="lg" sx={{ py: 4 }}>
        <Alert severity="warning">Please log in to access social features.</Alert>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 3, fontWeight: 600 }}>
        Social Hub
      </Typography>

      <Paper elevation={0} sx={{ border: '1px solid', borderColor: 'divider' }}>
        <Tabs
          value={tabValue}
          onChange={handleTabChange}
          variant="fullWidth"
          sx={{
            borderBottom: '1px solid',
            borderColor: 'divider',
            '& .MuiTab-root': { minHeight: 64 },
          }}
        >
          <Tab
            icon={<SearchIcon />}
            label="Find Users"
            iconPosition="start"
          />
          <Tab
            icon={
              <Badge
                badgeContent={friendRequests?.incoming_count || 0}
                color="error"
                max={99}
              >
                <RequestsIcon />
              </Badge>
            }
            label="Friend Requests"
            iconPosition="start"
          />
          <Tab
            icon={<PeopleIcon />}
            label="Friends"
            iconPosition="start"
          />
          <Tab
            icon={
              <Badge
                badgeContent={unreadCounts?.total_unread || 0}
                color="primary"
                max={99}
              >
                <MessagesIcon />
              </Badge>
            }
            label="Messages"
            iconPosition="start"
          />
        </Tabs>

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
            <CircularProgress />
          </Box>
        ) : (
          <>
            {error && (
              <Alert severity="error" sx={{ m: 2 }}>
                {error}
              </Alert>
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
