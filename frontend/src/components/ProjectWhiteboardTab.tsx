import React, { useState, useEffect } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardActionArea,
  Typography,
  Button,
  Grid,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  IconButton,
  Tooltip,
  Chip,
  Stack,
  alpha,
  useTheme,
  CircularProgress,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DrawIcon from '@mui/icons-material/Draw';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import PersonIcon from '@mui/icons-material/Person';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import GridOnIcon from '@mui/icons-material/GridOn';
import { useNavigate } from 'react-router-dom';
import { whiteboardClient, WhiteboardSummary } from '../api/client';

interface ProjectWhiteboardTabProps {
  projectId: number;
}

const ProjectWhiteboardTab: React.FC<ProjectWhiteboardTabProps> = ({ projectId }) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [whiteboards, setWhiteboards] = useState<WhiteboardSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newWhiteboardName, setNewWhiteboardName] = useState('');
  const [newWhiteboardDescription, setNewWhiteboardDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const [selectedWhiteboardId, setSelectedWhiteboardId] = useState<number | null>(null);

  useEffect(() => {
    loadWhiteboards();
  }, [projectId]);

  const loadWhiteboards = async () => {
    setLoading(true);
    try {
      const data = await whiteboardClient.getProjectWhiteboards(projectId);
      setWhiteboards(data);
    } catch (error) {
      console.error('Failed to load whiteboards:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    if (!newWhiteboardName.trim()) return;
    
    setCreating(true);
    try {
      const newWhiteboard = await whiteboardClient.create({
        project_id: projectId,
        name: newWhiteboardName.trim(),
        description: newWhiteboardDescription.trim() || undefined,
      });
      
      // Navigate to the new whiteboard
      navigate(`/projects/${projectId}/whiteboard/${newWhiteboard.id}?projectId=${projectId}`);
    } catch (error) {
      console.error('Failed to create whiteboard:', error);
    } finally {
      setCreating(false);
      setCreateDialogOpen(false);
      setNewWhiteboardName('');
      setNewWhiteboardDescription('');
    }
  };

  const handleOpenWhiteboard = (whiteboardId: number) => {
    navigate(`/projects/${projectId}/whiteboard/${whiteboardId}?projectId=${projectId}`);
  };

  const handleDeleteWhiteboard = async () => {
    if (!selectedWhiteboardId) return;
    
    try {
      await whiteboardClient.delete(selectedWhiteboardId);
      setWhiteboards(prev => prev.filter(w => w.id !== selectedWhiteboardId));
    } catch (error) {
      console.error('Failed to delete whiteboard:', error);
    }
    setMenuAnchor(null);
    setSelectedWhiteboardId(null);
  };

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      year: date.getFullYear() !== new Date().getFullYear() ? 'numeric' : undefined 
    });
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: 300 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h5" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 1 }}>
          <DrawIcon sx={{ color: theme.palette.primary.main }} />
          Collaborative Whiteboards
        </Typography>
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={() => setCreateDialogOpen(true)}
          sx={{
            background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            '&:hover': {
              background: `linear-gradient(135deg, ${theme.palette.primary.dark}, ${theme.palette.secondary.dark})`,
            },
          }}
        >
          New Whiteboard
        </Button>
      </Box>

      {/* Whiteboards Grid */}
      <Grid container spacing={3}>
        {whiteboards.map((whiteboard) => (
          <Grid item xs={12} sm={6} md={4} key={whiteboard.id}>
            <Card
              sx={{
                height: '100%',
                background: alpha(theme.palette.background.paper, 0.9),
                backdropFilter: 'blur(10px)',
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                transition: 'all 0.3s ease',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: `0 12px 40px ${alpha(theme.palette.primary.main, 0.2)}`,
                  border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
                },
              }}
            >
              <CardActionArea 
                onClick={() => handleOpenWhiteboard(whiteboard.id)}
                sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
              >
                {/* Preview Area */}
                <Box
                  sx={{
                    height: 120,
                    background: `linear-gradient(135deg, ${alpha('#1e1e2e', 0.95)} 0%, ${alpha('#2d2d4a', 0.9)} 100%)`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    position: 'relative',
                    overflow: 'hidden',
                  }}
                >
                  {/* Grid pattern overlay */}
                  <Box
                    sx={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      bottom: 0,
                      backgroundImage: `
                        linear-gradient(${alpha('#ffffff', 0.05)} 1px, transparent 1px),
                        linear-gradient(90deg, ${alpha('#ffffff', 0.05)} 1px, transparent 1px)
                      `,
                      backgroundSize: '20px 20px',
                    }}
                  />
                  <GridOnIcon sx={{ fontSize: 60, color: alpha('#ffffff', 0.1) }} />
                  
                  {/* Locked badge */}
                  {whiteboard.is_locked && (
                    <Chip
                      size="small"
                      label="Locked"
                      sx={{
                        position: 'absolute',
                        top: 8,
                        right: 8,
                        bgcolor: alpha('#f59e0b', 0.2),
                        color: '#f59e0b',
                        fontSize: '0.65rem',
                      }}
                    />
                  )}

                  {/* Active users badge */}
                  {whiteboard.active_users > 0 && (
                    <Chip
                      icon={<PersonIcon sx={{ fontSize: 14, color: '#22c55e !important' }} />}
                      size="small"
                      label={`${whiteboard.active_users} active`}
                      sx={{
                        position: 'absolute',
                        top: 8,
                        left: 8,
                        bgcolor: alpha('#22c55e', 0.2),
                        color: '#22c55e',
                        fontSize: '0.65rem',
                      }}
                    />
                  )}
                </Box>

                <CardContent sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <Typography variant="h6" sx={{ fontWeight: 600, mb: 0.5 }}>
                      {whiteboard.name}
                    </Typography>
                    <IconButton
                      size="small"
                      onClick={(e) => {
                        e.stopPropagation();
                        setMenuAnchor(e.currentTarget);
                        setSelectedWhiteboardId(whiteboard.id);
                      }}
                    >
                      <MoreVertIcon fontSize="small" />
                    </IconButton>
                  </Box>

                  {whiteboard.description && (
                    <Typography
                      variant="body2"
                      color="text.secondary"
                      sx={{
                        mb: 1,
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        display: '-webkit-box',
                        WebkitLineClamp: 2,
                        WebkitBoxOrient: 'vertical',
                      }}
                    >
                      {whiteboard.description}
                    </Typography>
                  )}

                  <Box sx={{ mt: 'auto' }}>
                    <Stack direction="row" spacing={1} alignItems="center">
                      <Chip
                        size="small"
                        label={`${whiteboard.element_count} elements`}
                        variant="outlined"
                        sx={{ fontSize: '0.7rem' }}
                      />
                      <Stack direction="row" spacing={0.5} alignItems="center" sx={{ color: 'text.secondary' }}>
                        <AccessTimeIcon sx={{ fontSize: 14 }} />
                        <Typography variant="caption">
                          {formatDate(whiteboard.updated_at || whiteboard.created_at)}
                        </Typography>
                      </Stack>
                    </Stack>
                  </Box>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}

        {/* Create New Card */}
        <Grid item xs={12} sm={6} md={4}>
          <Card
            sx={{
              height: '100%',
              minHeight: 220,
              background: alpha(theme.palette.background.paper, 0.5),
              border: `2px dashed ${alpha(theme.palette.primary.main, 0.3)}`,
              transition: 'all 0.3s ease',
              cursor: 'pointer',
              '&:hover': {
                border: `2px dashed ${theme.palette.primary.main}`,
                background: alpha(theme.palette.primary.main, 0.05),
              },
            }}
            onClick={() => setCreateDialogOpen(true)}
          >
            <CardActionArea sx={{ height: '100%', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <AddIcon sx={{ fontSize: 48, color: alpha(theme.palette.primary.main, 0.5), mb: 1 }} />
              <Typography variant="h6" color="text.secondary">
                Create New Whiteboard
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Collaborate with your team in real-time
              </Typography>
            </CardActionArea>
          </Card>
        </Grid>
      </Grid>

      {/* Empty State */}
      {whiteboards.length === 0 && (
        <Box
          sx={{
            textAlign: 'center',
            py: 8,
            px: 4,
            background: alpha(theme.palette.background.paper, 0.5),
            borderRadius: 3,
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <DrawIcon sx={{ fontSize: 64, color: alpha(theme.palette.primary.main, 0.3), mb: 2 }} />
          <Typography variant="h5" sx={{ mb: 1 }}>
            No whiteboards yet
          </Typography>
          <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
            Create your first whiteboard to start collaborating with your team.
            Draw diagrams, annotate screenshots, and brainstorm together in real-time.
          </Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
            sx={{
              background: `linear-gradient(135deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              px: 4,
              py: 1.5,
            }}
          >
            Create First Whiteboard
          </Button>
        </Box>
      )}

      {/* Create Dialog */}
      <Dialog 
        open={createDialogOpen} 
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle sx={{ fontWeight: 600 }}>
          Create New Whiteboard
        </DialogTitle>
        <DialogContent>
          <TextField
            autoFocus
            fullWidth
            label="Whiteboard Name"
            value={newWhiteboardName}
            onChange={(e) => setNewWhiteboardName(e.target.value)}
            sx={{ mt: 1, mb: 2 }}
            placeholder="e.g., Architecture Diagram, Attack Flow, Notes"
          />
          <TextField
            fullWidth
            multiline
            rows={2}
            label="Description (optional)"
            value={newWhiteboardDescription}
            onChange={(e) => setNewWhiteboardDescription(e.target.value)}
            placeholder="What's this whiteboard for?"
          />
        </DialogContent>
        <DialogActions sx={{ px: 3, pb: 2 }}>
          <Button onClick={() => setCreateDialogOpen(false)}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleCreate}
            disabled={!newWhiteboardName.trim() || creating}
            startIcon={creating ? <CircularProgress size={16} /> : <AddIcon />}
          >
            {creating ? 'Creating...' : 'Create Whiteboard'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchor}
        open={Boolean(menuAnchor)}
        onClose={() => {
          setMenuAnchor(null);
          setSelectedWhiteboardId(null);
        }}
      >
        <MenuItem onClick={() => {
          if (selectedWhiteboardId) handleOpenWhiteboard(selectedWhiteboardId);
          setMenuAnchor(null);
        }}>
          <ListItemIcon><OpenInNewIcon fontSize="small" /></ListItemIcon>
          <ListItemText>Open</ListItemText>
        </MenuItem>
        <MenuItem 
          onClick={handleDeleteWhiteboard}
          sx={{ color: 'error.main' }}
        >
          <ListItemIcon><DeleteIcon fontSize="small" color="error" /></ListItemIcon>
          <ListItemText>Delete</ListItemText>
        </MenuItem>
      </Menu>
    </Box>
  );
};

export default ProjectWhiteboardTab;
