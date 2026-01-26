import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction,
  Avatar,
  IconButton,
  Menu,
  MenuItem,
  CircularProgress,
  Alert,
  Chip,
  Divider,
  Tabs,
  Tab,
} from '@mui/material';
import {
  Settings as SettingsIcon,
  PersonAdd as PersonAddIcon,
  MoreVert as MoreVertIcon,
  Shield as ShieldIcon,
  Star as StarIcon,
  Person as PersonIcon,
  ExitToApp as LeaveIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import { socialApi, GroupMemberInfo, ParticipantRole, Friend, ConversationDetail } from '../../api/client';
import { useAuth } from '../../contexts/AuthContext';

interface GroupSettingsDialogProps {
  open: boolean;
  onClose: () => void;
  conversation: ConversationDetail;
  onGroupUpdated: () => void;
  onLeftGroup: () => void;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel({ children, value, index }: TabPanelProps) {
  return (
    <div hidden={value !== index} style={{ paddingTop: 16 }}>
      {value === index && children}
    </div>
  );
}

export default function GroupSettingsDialog({ 
  open, 
  onClose, 
  conversation, 
  onGroupUpdated,
  onLeftGroup 
}: GroupSettingsDialogProps) {
  const { user } = useAuth();
  const [tab, setTab] = useState(0);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [members, setMembers] = useState<GroupMemberInfo[]>([]);
  const [friends, setFriends] = useState<Friend[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Menu state
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);
  const [selectedMember, setSelectedMember] = useState<GroupMemberInfo | null>(null);
  
  // Leave group confirmation dialog state
  const [showLeaveConfirm, setShowLeaveConfirm] = useState(false);
  const [leaving, setLeaving] = useState(false);

  const myRole = conversation.my_role || 'member';
  const isOwner = myRole === 'owner';
  const isAdmin = myRole === 'owner' || myRole === 'admin';

  useEffect(() => {
    if (open) {
      setName(conversation.name || '');
      setDescription(conversation.description || '');
      loadMembers();
      if (isAdmin) {
        loadFriends();
      }
      setTab(0);
      setError('');
      setSuccess('');
    }
  }, [open, conversation.id]);

  const loadMembers = async () => {
    setLoadingMembers(true);
    try {
      const result = await socialApi.getGroupMembers(conversation.id);
      setMembers(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load members');
    } finally {
      setLoadingMembers(false);
    }
  };

  const loadFriends = async () => {
    try {
      const result = await socialApi.getFriends();
      setFriends(result.friends);
    } catch (err) {
      console.error('Failed to load friends:', err);
    }
  };

  const handleUpdateSettings = async () => {
    if (!name.trim()) {
      setError('Group name is required');
      return;
    }

    setLoading(true);
    setError('');
    try {
      await socialApi.updateGroup(conversation.id, {
        name: name.trim(),
        description: description.trim() || undefined,
      });
      setSuccess('Group settings updated');
      onGroupUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update group');
    } finally {
      setLoading(false);
    }
  };

  const handleAddMember = async (friendId: number) => {
    setLoading(true);
    setError('');
    try {
      await socialApi.addGroupMembers(conversation.id, [friendId]);
      loadMembers();
      setSuccess('Member added');
      onGroupUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add member');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveMember = async (userId: number) => {
    setLoading(true);
    setError('');
    try {
      await socialApi.removeGroupMember(conversation.id, userId);
      loadMembers();
      setSuccess('Member removed');
      onGroupUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove member');
    } finally {
      setLoading(false);
    }
    setMenuAnchor(null);
    setSelectedMember(null);
  };

  const handleUpdateRole = async (userId: number, role: ParticipantRole) => {
    setLoading(true);
    setError('');
    try {
      await socialApi.updateMemberRole(conversation.id, userId, role);
      loadMembers();
      setSuccess(`Role updated to ${role}`);
      onGroupUpdated();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update role');
    } finally {
      setLoading(false);
    }
    setMenuAnchor(null);
    setSelectedMember(null);
  };

  const handleLeaveGroup = async () => {
    if (!user?.id) return;
    
    setLeaving(true);
    try {
      await socialApi.leaveGroup(conversation.id, user.id);
      onLeftGroup();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to leave group');
      setLeaving(false);
      setShowLeaveConfirm(false);
    }
  };

  const handleLeaveClick = () => {
    setShowLeaveConfirm(true);
  };

  const getRoleIcon = (role: ParticipantRole) => {
    switch (role) {
      case 'owner': return <StarIcon sx={{ fontSize: 16, color: 'warning.main' }} />;
      case 'admin': return <ShieldIcon sx={{ fontSize: 16, color: 'primary.main' }} />;
      default: return <PersonIcon sx={{ fontSize: 16, color: 'text.secondary' }} />;
    }
  };

  const getRoleLabel = (role: ParticipantRole) => {
    switch (role) {
      case 'owner': return 'Owner';
      case 'admin': return 'Admin';
      default: return 'Member';
    }
  };

  // Find friends not in group
  const friendsNotInGroup = friends.filter(
    f => !members.some(m => m.user_id === f.user_id)
  );

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SettingsIcon color="primary" />
          Group Settings
        </Box>
      </DialogTitle>
      <DialogContent>
        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}
        {success && (
          <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess('')}>
            {success}
          </Alert>
        )}

        <Tabs value={tab} onChange={(_, v) => setTab(v)}>
          <Tab label="Settings" />
          <Tab label={`Members (${members.length})`} />
          {isAdmin && <Tab label="Add Members" />}
        </Tabs>

        <TabPanel value={tab} index={0}>
          <TextField
            fullWidth
            label="Group Name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            margin="normal"
            disabled={!isAdmin}
            inputProps={{ maxLength: 100 }}
          />

          <TextField
            fullWidth
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            margin="normal"
            multiline
            rows={3}
            disabled={!isAdmin}
            inputProps={{ maxLength: 500 }}
          />

          {isAdmin && (
            <Button
              variant="contained"
              onClick={handleUpdateSettings}
              disabled={loading || !name.trim()}
              sx={{ mt: 2 }}
            >
              {loading ? <CircularProgress size={20} /> : 'Save Changes'}
            </Button>
          )}

          <Divider sx={{ my: 3 }} />

          <Button
            color="error"
            startIcon={<LeaveIcon />}
            onClick={handleLeaveClick}
            disabled={loading || leaving || isOwner}
          >
            Leave Group
          </Button>
          {isOwner && (
            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
              Transfer ownership before leaving
            </Typography>
          )}
        </TabPanel>

        <TabPanel value={tab} index={1}>
          {loadingMembers ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
              <CircularProgress size={24} />
            </Box>
          ) : (
            <List>
              {members.map(member => (
                <ListItem key={member.user_id}>
                  <ListItemAvatar>
                    <Avatar src={member.avatar_url}>
                      {member.username[0].toUpperCase()}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {member.username}
                        {member.user_id === user?.id && (
                          <Chip label="You" size="small" />
                        )}
                      </Box>
                    }
                    secondary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {getRoleIcon(member.role)}
                        {getRoleLabel(member.role)}
                      </Box>
                    }
                  />
                  {isOwner && member.user_id !== user?.id && (
                    <ListItemSecondaryAction>
                      <IconButton
                        onClick={(e) => {
                          setMenuAnchor(e.currentTarget);
                          setSelectedMember(member);
                        }}
                      >
                        <MoreVertIcon />
                      </IconButton>
                    </ListItemSecondaryAction>
                  )}
                </ListItem>
              ))}
            </List>
          )}
        </TabPanel>

        {isAdmin && (
          <TabPanel value={tab} index={2}>
            {friendsNotInGroup.length === 0 ? (
              <Typography color="text.secondary" sx={{ py: 2, textAlign: 'center' }}>
                All your contacts are already in this group
              </Typography>
            ) : (
              <List>
                {friendsNotInGroup.map(friend => (
                  <ListItem key={friend.user_id}>
                    <ListItemAvatar>
                      <Avatar src={friend.avatar_url}>
                        {friend.username[0].toUpperCase()}
                      </Avatar>
                    </ListItemAvatar>
                    <ListItemText
                      primary={friend.username}
                      secondary={friend.first_name ? `${friend.first_name} ${friend.last_name || ''}`.trim() : undefined}
                    />
                    <ListItemSecondaryAction>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<PersonAddIcon />}
                        onClick={() => handleAddMember(friend.user_id)}
                        disabled={loading}
                      >
                        Add
                      </Button>
                    </ListItemSecondaryAction>
                  </ListItem>
                ))}
              </List>
            )}
          </TabPanel>
        )}

        {/* Member action menu */}
        <Menu
          anchorEl={menuAnchor}
          open={Boolean(menuAnchor)}
          onClose={() => {
            setMenuAnchor(null);
            setSelectedMember(null);
          }}
        >
          {selectedMember?.role === 'admin' ? (
            <MenuItem onClick={() => selectedMember && handleUpdateRole(selectedMember.user_id, 'member')}>
              <PersonIcon sx={{ mr: 1 }} /> Demote to Member
            </MenuItem>
          ) : selectedMember?.role === 'member' ? (
            <MenuItem onClick={() => selectedMember && handleUpdateRole(selectedMember.user_id, 'admin')}>
              <ShieldIcon sx={{ mr: 1 }} /> Promote to Admin
            </MenuItem>
          ) : null}
          
          {selectedMember?.role !== 'owner' && (
            <MenuItem onClick={() => selectedMember && handleUpdateRole(selectedMember.user_id, 'owner')}>
              <StarIcon sx={{ mr: 1 }} /> Transfer Ownership
            </MenuItem>
          )}
          
          <Divider />
          
          <MenuItem 
            onClick={() => selectedMember && handleRemoveMember(selectedMember.user_id)}
            sx={{ color: 'error.main' }}
          >
            <DeleteIcon sx={{ mr: 1 }} /> Remove from Group
          </MenuItem>
        </Menu>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>

      {/* Leave Group Confirmation Dialog */}
      <Dialog
        open={showLeaveConfirm}
        onClose={() => !leaving && setShowLeaveConfirm(false)}
      >
        <DialogTitle>Leave Group?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to leave <strong>{conversation.name || 'this group'}</strong>?
            You can be re-added by an admin later.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setShowLeaveConfirm(false)} disabled={leaving}>
            Cancel
          </Button>
          <Button
            color="error"
            variant="contained"
            onClick={handleLeaveGroup}
            disabled={leaving}
            startIcon={leaving ? <CircularProgress size={16} /> : <LeaveIcon />}
          >
            {leaving ? 'Leaving...' : 'Leave Group'}
          </Button>
        </DialogActions>
      </Dialog>
    </Dialog>
  );
}
