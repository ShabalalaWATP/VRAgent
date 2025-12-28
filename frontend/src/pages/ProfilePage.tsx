import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Typography,
  Paper,
  Avatar,
  Divider,
  TextField,
  Button,
  Alert,
  Chip,
  Grid,
  Card,
  CardContent,
  IconButton,
  InputAdornment,
  CircularProgress,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  ListItemSecondaryAction,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
} from '@mui/material';
import {
  Person as PersonIcon,
  Email as EmailIcon,
  Badge as BadgeIcon,
  CalendarToday as CalendarIcon,
  Lock as LockIcon,
  Visibility,
  VisibilityOff,
  AdminPanelSettings as AdminIcon,
  CheckCircle as ApprovedIcon,
  Schedule as PendingIcon,
  Block as SuspendedIcon,
  Save as SaveIcon,
  Note as NoteIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
} from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';
import { socialApi, UserNote } from '../api/client';

const API_BASE = import.meta.env.VITE_API_URL || '/api';

export default function ProfilePage() {
  const { user, getAccessToken } = useAuth();
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  // Notes state
  const [notes, setNotes] = useState<UserNote[]>([]);
  const [notesLoading, setNotesLoading] = useState(true);
  const [notesExpanded, setNotesExpanded] = useState(false);
  const [editingNote, setEditingNote] = useState<UserNote | null>(null);
  const [editNoteContent, setEditNoteContent] = useState('');
  const [noteError, setNoteError] = useState('');
  const [noteSaving, setNoteSaving] = useState(false);

  // Load notes
  useEffect(() => {
    const loadNotes = async () => {
      try {
        const result = await socialApi.getAllNotes();
        setNotes(result.notes);
      } catch (err) {
        console.error('Failed to load notes:', err);
      } finally {
        setNotesLoading(false);
      }
    };
    loadNotes();
  }, []);

  if (!user) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Alert severity="warning">Please log in to view your profile.</Alert>
      </Container>
    );
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    // Validation
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long');
      return;
    }

    if (newPassword !== confirmPassword) {
      setError('New passwords do not match');
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE}/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${getAccessToken()}`,
        },
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Failed to change password');
      }

      setSuccess('Password changed successfully!');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'approved':
        return <ApprovedIcon sx={{ color: 'success.main' }} />;
      case 'pending':
        return <PendingIcon sx={{ color: 'warning.main' }} />;
      case 'suspended':
        return <SuspendedIcon sx={{ color: 'error.main' }} />;
      default:
        return null;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'approved':
        return 'success';
      case 'pending':
        return 'warning';
      case 'suspended':
        return 'error';
      default:
        return 'default';
    }
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const handleEditNote = (note: UserNote) => {
    setEditingNote(note);
    setEditNoteContent(note.content);
    setNoteError('');
  };

  const handleSaveNote = async () => {
    if (!editingNote || !editNoteContent.trim()) return;
    
    setNoteSaving(true);
    setNoteError('');
    try {
      await socialApi.createOrUpdateNote(editingNote.subject_id, editNoteContent.trim());
      // Update local state
      setNotes(notes.map(n => 
        n.subject_id === editingNote.subject_id 
          ? { ...n, content: editNoteContent.trim(), updated_at: new Date().toISOString() }
          : n
      ));
      setEditingNote(null);
    } catch (err) {
      setNoteError(err instanceof Error ? err.message : 'Failed to save note');
    } finally {
      setNoteSaving(false);
    }
  };

  const handleDeleteNote = async (subjectId: number) => {
    if (!confirm('Are you sure you want to delete this note?')) return;
    
    try {
      await socialApi.deleteNote(subjectId);
      setNotes(notes.filter(n => n.subject_id !== subjectId));
    } catch (err) {
      console.error('Failed to delete note:', err);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 4, fontWeight: 600 }}>
        My Profile
      </Typography>

      <Grid container spacing={3}>
        {/* Profile Info Card */}
        <Grid item xs={12} md={6}>
          <Card
            elevation={0}
            sx={{
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.1) 0%, rgba(139, 92, 246, 0.1) 100%)',
              border: '1px solid',
              borderColor: 'divider',
              height: '100%',
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
                <Avatar
                  sx={{
                    width: 80,
                    height: 80,
                    bgcolor: user.role === 'admin' ? 'secondary.main' : 'primary.main',
                    fontSize: '2rem',
                  }}
                >
                  {user.username.charAt(0).toUpperCase()}
                </Avatar>
                <Box sx={{ ml: 2 }}>
                  <Typography variant="h5" fontWeight={600}>
                    {user.username}
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
                    <Chip
                      size="small"
                      icon={user.role === 'admin' ? <AdminIcon /> : <PersonIcon />}
                      label={user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                      color={user.role === 'admin' ? 'secondary' : 'primary'}
                      variant="outlined"
                    />
                    <Chip
                      size="small"
                      icon={getStatusIcon(user.status) || undefined}
                      label={user.status.charAt(0).toUpperCase() + user.status.slice(1)}
                      color={getStatusColor(user.status) as 'success' | 'warning' | 'error' | 'default'}
                      variant="outlined"
                    />
                  </Box>
                </Box>
              </Box>

              <Divider sx={{ my: 2 }} />

              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                  <EmailIcon color="action" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Email
                    </Typography>
                    <Typography variant="body1">{user.email}</Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                  <BadgeIcon color="action" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Username
                    </Typography>
                    <Typography variant="body1">{user.username}</Typography>
                  </Box>
                </Box>

                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                  <CalendarIcon color="action" />
                  <Box>
                    <Typography variant="caption" color="text.secondary">
                      Member Since
                    </Typography>
                    <Typography variant="body1">{formatDate(user.created_at)}</Typography>
                  </Box>
                </Box>

                {user.last_login && (
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                    <LockIcon color="action" />
                    <Box>
                      <Typography variant="caption" color="text.secondary">
                        Last Login
                      </Typography>
                      <Typography variant="body1">{formatDate(user.last_login)}</Typography>
                    </Box>
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Change Password Card */}
        <Grid item xs={12} md={6}>
          <Card
            elevation={0}
            sx={{
              border: '1px solid',
              borderColor: 'divider',
              height: '100%',
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <LockIcon /> Change Password
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Update your password to keep your account secure.
              </Typography>

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

              <Box component="form" onSubmit={handlePasswordChange}>
                <TextField
                  fullWidth
                  label="Current Password"
                  type={showCurrentPassword ? 'text' : 'password'}
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                  sx={{ mb: 2 }}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                          edge="end"
                        >
                          {showCurrentPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />

                <TextField
                  fullWidth
                  label="New Password"
                  type={showNewPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  helperText="At least 8 characters"
                  sx={{ mb: 2 }}
                  InputProps={{
                    endAdornment: (
                      <InputAdornment position="end">
                        <IconButton
                          onClick={() => setShowNewPassword(!showNewPassword)}
                          edge="end"
                        >
                          {showNewPassword ? <VisibilityOff /> : <Visibility />}
                        </IconButton>
                      </InputAdornment>
                    ),
                  }}
                />

                <TextField
                  fullWidth
                  label="Confirm New Password"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  error={confirmPassword !== '' && confirmPassword !== newPassword}
                  helperText={
                    confirmPassword !== '' && confirmPassword !== newPassword
                      ? 'Passwords do not match'
                      : ''
                  }
                  sx={{ mb: 3 }}
                />

                <Button
                  type="submit"
                  variant="contained"
                  fullWidth
                  disabled={loading || !currentPassword || !newPassword || !confirmPassword}
                  startIcon={loading ? <CircularProgress size={20} /> : <SaveIcon />}
                >
                  {loading ? 'Changing Password...' : 'Change Password'}
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* User Notes Card */}
        <Grid item xs={12}>
          <Card
            elevation={0}
            sx={{
              border: '1px solid',
              borderColor: 'divider',
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box 
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'space-between',
                  cursor: 'pointer',
                }}
                onClick={() => setNotesExpanded(!notesExpanded)}
              >
                <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <NoteIcon /> My Notes About Others
                  <Chip 
                    label={notes.length} 
                    size="small" 
                    color="primary" 
                    sx={{ ml: 1 }}
                  />
                </Typography>
                <IconButton size="small">
                  {notesExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                </IconButton>
              </Box>
              
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Private notes you've written about other users. Only you can see these.
              </Typography>

              <Collapse in={notesExpanded}>
                <Box sx={{ mt: 2 }}>
                  {notesLoading ? (
                    <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
                      <CircularProgress size={24} />
                    </Box>
                  ) : notes.length === 0 ? (
                    <Box sx={{ textAlign: 'center', py: 3 }}>
                      <NoteIcon sx={{ fontSize: 48, color: 'text.disabled', mb: 1 }} />
                      <Typography color="text.secondary">
                        No notes yet. You can add notes about users from their profile or the social page.
                      </Typography>
                    </Box>
                  ) : (
                    <List>
                      {notes.map((note) => (
                        <ListItem
                          key={note.subject_id}
                          sx={{
                            border: '1px solid',
                            borderColor: 'divider',
                            borderRadius: 1,
                            mb: 1,
                          }}
                        >
                          <ListItemAvatar>
                            <Avatar sx={{ bgcolor: 'primary.main' }}>
                              {note.subject_username?.charAt(0).toUpperCase() || '?'}
                            </Avatar>
                          </ListItemAvatar>
                          <ListItemText
                            primary={
                              <Typography variant="subtitle2" fontWeight={500}>
                                {note.subject_username}
                              </Typography>
                            }
                            secondary={
                              <Box>
                                <Typography 
                                  variant="body2" 
                                  sx={{ 
                                    mt: 0.5,
                                    whiteSpace: 'pre-wrap',
                                    color: 'text.primary',
                                  }}
                                >
                                  {note.content}
                                </Typography>
                                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                  Updated: {new Date(note.updated_at).toLocaleDateString()}
                                </Typography>
                              </Box>
                            }
                          />
                          <ListItemSecondaryAction>
                            <IconButton 
                              size="small" 
                              onClick={() => handleEditNote(note)}
                              sx={{ mr: 0.5 }}
                            >
                              <EditIcon fontSize="small" />
                            </IconButton>
                            <IconButton 
                              size="small" 
                              color="error"
                              onClick={() => handleDeleteNote(note.subject_id)}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </ListItemSecondaryAction>
                        </ListItem>
                      ))}
                    </List>
                  )}
                </Box>
              </Collapse>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Edit Note Dialog */}
      <Dialog open={!!editingNote} onClose={() => setEditingNote(null)} maxWidth="sm" fullWidth>
        <DialogTitle>
          Edit Note about {editingNote?.subject_username}
        </DialogTitle>
        <DialogContent>
          {noteError && (
            <Alert severity="error" sx={{ mb: 2 }} onClose={() => setNoteError('')}>
              {noteError}
            </Alert>
          )}
          <TextField
            fullWidth
            multiline
            rows={4}
            placeholder="Write your private note here..."
            value={editNoteContent}
            onChange={(e) => setEditNoteContent(e.target.value)}
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditingNote(null)}>Cancel</Button>
          <Button 
            variant="contained" 
            onClick={handleSaveNote}
            disabled={noteSaving || !editNoteContent.trim()}
            startIcon={noteSaving ? <CircularProgress size={16} /> : <SaveIcon />}
          >
            Save Note
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  );
}
