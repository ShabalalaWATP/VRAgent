/**
 * CardDetailDialog - Detailed view/edit dialog for a Kanban card
 */
import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Box,
  Typography,
  TextField,
  Button,
  IconButton,
  Chip,
  Avatar,
  AvatarGroup,
  Divider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  Checkbox,
  Tooltip,
  Menu,
  Grid,
  Alert,
  Autocomplete,
} from '@mui/material';
import {
  Close as CloseIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Flag as FlagIcon,
  Schedule as ScheduleIcon,
  Person as PersonIcon,
  Label as LabelIcon,
  Add as AddIcon,
  Check as CheckIcon,
  CheckBoxOutlineBlank as UncheckedIcon,
  CheckBox as CheckedIcon,
  Send as SendIcon,
  BugReport as BugIcon,
  Link as LinkIcon,
  Palette as PaletteIcon,
} from '@mui/icons-material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { format } from 'date-fns';
import { CardData, CardLabel, ChecklistItem, AssigneeInfo } from './KanbanCard';
import { ColumnData } from './KanbanBoard';
import { kanbanApi, api, ProjectCollaborator } from '../../api/client';

interface CardDetailDialogProps {
  open: boolean;
  card: CardData;
  columns: ColumnData[];
  projectId: number;
  onClose: () => void;
  onUpdate: () => void;
  onDelete: () => void;
  onFindingClick?: (findingId: number) => void;
}

interface ProjectMember {
  user_id: number;
  username: string;
  email?: string;
  role: string;
}

interface CommentData {
  id: number;
  user_id: number;
  username: string;
  user_avatar_url?: string;
  content: string;
  created_at: string;
}

const priorityOptions = [
  { value: '', label: 'None', color: '#9e9e9e' },
  { value: 'low', label: 'Low', color: '#4caf50' },
  { value: 'medium', label: 'Medium', color: '#ff9800' },
  { value: 'high', label: 'High', color: '#f44336' },
  { value: 'critical', label: 'Critical', color: '#d32f2f' },
];

const labelColors = [
  '#ef5350', '#ec407a', '#ab47bc', '#7e57c2',
  '#5c6bc0', '#42a5f5', '#29b6f6', '#26c6da',
  '#26a69a', '#66bb6a', '#9ccc65', '#d4e157',
  '#ffee58', '#ffca28', '#ffa726', '#ff7043',
];

// Card background colors (dark theme compatible)
const cardColors = [
  { value: '', label: 'Default', color: 'transparent' },
  { value: '#4a3728', label: 'Brown', color: '#4a3728' },
  { value: '#2d4a3e', label: 'Dark Green', color: '#2d4a3e' },
  { value: '#2a3f5f', label: 'Dark Blue', color: '#2a3f5f' },
  { value: '#4a2d4a', label: 'Dark Purple', color: '#4a2d4a' },
  { value: '#4a2d3a', label: 'Dark Pink', color: '#4a2d3a' },
  { value: '#4a4a2d', label: 'Olive', color: '#4a4a2d' },
  { value: '#2d4a4a', label: 'Teal', color: '#2d4a4a' },
  { value: '#5c3d2e', label: 'Rust', color: '#5c3d2e' },
  { value: '#3d3d5c', label: 'Slate', color: '#3d3d5c' },
  { value: '#bf360c', label: 'Deep Orange', color: '#bf360c' },
  { value: '#1565c0', label: 'Blue', color: '#1565c0' },
  { value: '#2e7d32', label: 'Green', color: '#2e7d32' },
  { value: '#ad1457', label: 'Pink', color: '#ad1457' },
  { value: '#6a1b9a', label: 'Purple', color: '#6a1b9a' },
  { value: '#f9a825', label: 'Yellow', color: '#f9a825' },
];

export const CardDetailDialog: React.FC<CardDetailDialogProps> = ({
  open,
  card: initialCard,
  columns,
  projectId,
  onClose,
  onUpdate,
  onDelete,
  onFindingClick,
}) => {
  const [isEditing, setIsEditing] = useState(true); // Start in edit mode for better UX
  const [card, setCard] = useState<CardData>(initialCard);
  const [editedCard, setEditedCard] = useState<Partial<CardData>>({});
  const [saving, setSaving] = useState(false);
  
  // Comments
  const [comments, setComments] = useState<CommentData[]>([]);
  const [newComment, setNewComment] = useState('');
  const [loadingComments, setLoadingComments] = useState(false);
  
  // Checklist
  const [newChecklistItem, setNewChecklistItem] = useState('');
  
  // Label menu
  const [labelAnchor, setLabelAnchor] = useState<null | HTMLElement>(null);
  const [newLabelName, setNewLabelName] = useState('');
  const [newLabelColor, setNewLabelColor] = useState(labelColors[0]);
  
  // Project members for assignee selection
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  
  // Color picker
  const [colorAnchor, setColorAnchor] = useState<null | HTMLElement>(null);
  
  useEffect(() => {
    setCard(initialCard);
    setEditedCard({});
    loadComments();
    loadProjectMembers();
  }, [initialCard]);
  
  const loadProjectMembers = async () => {
    try {
      setLoadingMembers(true);
      const collaborators = await api.getProjectCollaborators(projectId);
      // Also get project info to include owner
      const project = await api.getProject(projectId);
      
      const members: ProjectMember[] = collaborators.map((c: ProjectCollaborator) => ({
        user_id: c.user_id,
        username: c.username || `User ${c.user_id}`,
        email: c.email,
        role: c.role,
      }));
      
      // Add owner if not already in list
      if (project.owner_id && !members.find(m => m.user_id === project.owner_id)) {
        members.unshift({
          user_id: project.owner_id,
          username: project.owner_username || `User ${project.owner_id}`,
          role: 'owner',
        });
      }
      
      setProjectMembers(members);
    } catch (err) {
      console.error('Failed to load project members:', err);
    } finally {
      setLoadingMembers(false);
    }
  };
  
  const loadComments = async () => {
    try {
      setLoadingComments(true);
      const response = await kanbanApi.getCardComments(initialCard.id);
      setComments(response as CommentData[]);
    } catch (err) {
      console.error('Failed to load comments:', err);
    } finally {
      setLoadingComments(false);
    }
  };
  
  const handleSave = async () => {
    try {
      setSaving(true);
      await kanbanApi.updateCard(card.id, {
        title: editedCard.title ?? card.title,
        description: editedCard.description ?? card.description,
        priority: editedCard.priority ?? card.priority,
        labels: editedCard.labels ?? card.labels,
        due_date: editedCard.due_date ?? card.due_date,
        assignee_ids: editedCard.assignee_ids ?? card.assignee_ids,
        checklist: editedCard.checklist ?? card.checklist,
        color: editedCard.color ?? card.color,
      });
      setIsEditing(false);
      onUpdate();
    } catch (err) {
      console.error('Failed to save card:', err);
    } finally {
      setSaving(false);
    }
  };
  
  const handleColumnChange = async (newColumnId: number) => {
    try {
      await kanbanApi.moveCard(card.id, newColumnId, 0);
      onUpdate();
    } catch (err) {
      console.error('Failed to move card:', err);
    }
  };
  
  const handleAddComment = async () => {
    if (!newComment.trim()) return;
    
    try {
      await kanbanApi.addComment(card.id, newComment.trim());
      setNewComment('');
      loadComments();
    } catch (err) {
      console.error('Failed to add comment:', err);
    }
  };
  
  const handleDeleteComment = async (commentId: number) => {
    try {
      await kanbanApi.deleteComment(card.id, commentId);
      loadComments();
    } catch (err) {
      console.error('Failed to delete comment:', err);
    }
  };
  
  const handleToggleChecklistItem = async (itemId: string) => {
    const currentChecklist = editedCard.checklist ?? card.checklist ?? [];
    const updatedChecklist = currentChecklist.map(item =>
      item.id === itemId ? { ...item, completed: !item.completed } : item
    );
    
    setEditedCard({ ...editedCard, checklist: updatedChecklist });
    
    // Auto-save checklist changes
    try {
      await kanbanApi.updateCard(card.id, {
        checklist: updatedChecklist,
      });
      setCard({ ...card, checklist: updatedChecklist });
    } catch (err) {
      console.error('Failed to update checklist:', err);
    }
  };
  
  const handleAddChecklistItem = async () => {
    if (!newChecklistItem.trim()) return;
    
    const newItem: ChecklistItem = {
      id: `item-${Date.now()}`,
      text: newChecklistItem.trim(),
      completed: false,
    };
    
    const currentChecklist = editedCard.checklist ?? card.checklist ?? [];
    const updatedChecklist = [...currentChecklist, newItem];
    
    setEditedCard({ ...editedCard, checklist: updatedChecklist });
    setNewChecklistItem('');
    
    // Auto-save
    try {
      await kanbanApi.updateCard(card.id, {
        checklist: updatedChecklist,
      });
      setCard({ ...card, checklist: updatedChecklist });
    } catch (err) {
      console.error('Failed to add checklist item:', err);
    }
  };
  
  const handleDeleteChecklistItem = async (itemId: string) => {
    const currentChecklist = editedCard.checklist ?? card.checklist ?? [];
    const updatedChecklist = currentChecklist.filter(item => item.id !== itemId);
    
    setEditedCard({ ...editedCard, checklist: updatedChecklist });
    
    // Auto-save
    try {
      await kanbanApi.updateCard(card.id, {
        checklist: updatedChecklist,
      });
      setCard({ ...card, checklist: updatedChecklist });
    } catch (err) {
      console.error('Failed to delete checklist item:', err);
    }
  };
  
  const handleAddLabel = () => {
    if (!newLabelName.trim()) return;
    
    const newLabel: CardLabel = {
      name: newLabelName.trim(),
      color: newLabelColor,
    };
    
    const currentLabels = editedCard.labels ?? card.labels ?? [];
    setEditedCard({ ...editedCard, labels: [...currentLabels, newLabel] });
    setNewLabelName('');
    setLabelAnchor(null);
  };
  
  const handleRemoveLabel = (labelName: string) => {
    const currentLabels = editedCard.labels ?? card.labels ?? [];
    setEditedCard({ ...editedCard, labels: currentLabels.filter(l => l.name !== labelName) });
  };
  
  const currentColumn = columns.find(c => c.id === card.column_id);
  const currentChecklist = editedCard.checklist ?? card.checklist ?? [];
  const currentLabels = editedCard.labels ?? card.labels ?? [];
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 6 }}>
        {isEditing ? (
          <TextField
            fullWidth
            value={editedCard.title ?? card.title}
            onChange={(e) => setEditedCard({ ...editedCard, title: e.target.value })}
            variant="standard"
            sx={{ '& input': { fontSize: '1.25rem', fontWeight: 500 } }}
          />
        ) : (
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            {card.title}
          </Typography>
        )}
        <IconButton
          onClick={onClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      
      <DialogContent dividers>
        <Grid container spacing={3}>
          {/* Main Content */}
          <Grid item xs={12} md={8}>
            {/* Finding Link */}
            {card.finding_id && (
              <Alert
                severity="info"
                icon={<BugIcon />}
                action={
                  <Button
                    color="inherit"
                    size="small"
                    startIcon={<LinkIcon />}
                    onClick={() => onFindingClick?.(card.finding_id!)}
                  >
                    View Finding
                  </Button>
                }
                sx={{ mb: 2 }}
              >
                This card is linked to Finding #{card.finding_id}
              </Alert>
            )}
            
            {/* Description */}
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Description
            </Typography>
            {isEditing ? (
              <TextField
                fullWidth
                multiline
                rows={4}
                value={editedCard.description ?? card.description ?? ''}
                onChange={(e) => setEditedCard({ ...editedCard, description: e.target.value })}
                placeholder="Add a more detailed description..."
                sx={{ mb: 3 }}
              />
            ) : (
              <Typography
                variant="body2"
                sx={{
                  mb: 3,
                  whiteSpace: 'pre-wrap',
                  color: card.description ? 'text.primary' : 'text.secondary',
                  fontStyle: card.description ? 'normal' : 'italic',
                }}
              >
                {card.description || 'No description provided.'}
              </Typography>
            )}
            
            {/* Checklist */}
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Checklist
            </Typography>
            <List dense sx={{ mb: 2 }}>
              {currentChecklist.map((item) => (
                <ListItem key={item.id} disablePadding>
                  <ListItemIcon sx={{ minWidth: 36 }}>
                    <Checkbox
                      edge="start"
                      checked={item.completed}
                      onChange={() => handleToggleChecklistItem(item.id)}
                      icon={<UncheckedIcon />}
                      checkedIcon={<CheckedIcon />}
                    />
                  </ListItemIcon>
                  <ListItemText
                    primary={item.text}
                    sx={{
                      textDecoration: item.completed ? 'line-through' : 'none',
                      color: item.completed ? 'text.secondary' : 'text.primary',
                    }}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      size="small"
                      onClick={() => handleDeleteChecklistItem(item.id)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
            
            <Box sx={{ display: 'flex', gap: 1, mb: 3 }}>
              <TextField
                size="small"
                fullWidth
                placeholder="Add checklist item"
                value={newChecklistItem}
                onChange={(e) => setNewChecklistItem(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleAddChecklistItem()}
              />
              <Button
                variant="outlined"
                onClick={handleAddChecklistItem}
                disabled={!newChecklistItem.trim()}
              >
                Add
              </Button>
            </Box>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Comments */}
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Comments
            </Typography>
            
            <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
              <TextField
                fullWidth
                size="small"
                placeholder="Write a comment..."
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && !e.shiftKey && handleAddComment()}
                multiline
              />
              <IconButton
                color="primary"
                onClick={handleAddComment}
                disabled={!newComment.trim()}
              >
                <SendIcon />
              </IconButton>
            </Box>
            
            <List dense>
              {comments.map((comment) => (
                <ListItem key={comment.id} alignItems="flex-start" sx={{ px: 0 }}>
                  <ListItemIcon sx={{ minWidth: 40, mt: 0.5 }}>
                    <Avatar
                      src={comment.user_avatar_url}
                      sx={{ width: 32, height: 32 }}
                    >
                      {comment.username.charAt(0).toUpperCase()}
                    </Avatar>
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="subtitle2">{comment.username}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {format(new Date(comment.created_at), 'PPp')}
                        </Typography>
                      </Box>
                    }
                    secondary={comment.content}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      size="small"
                      onClick={() => handleDeleteComment(comment.id)}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
              {comments.length === 0 && !loadingComments && (
                <Typography variant="body2" color="text.secondary" sx={{ py: 2, textAlign: 'center' }}>
                  No comments yet
                </Typography>
              )}
            </List>
          </Grid>
          
          {/* Sidebar */}
          <Grid item xs={12} md={4}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              {/* Column (Move) */}
              <FormControl fullWidth size="small">
                <InputLabel>Column</InputLabel>
                <Select
                  value={card.column_id}
                  label="Column"
                  onChange={(e) => handleColumnChange(e.target.value as number)}
                >
                  {columns.map((col) => (
                    <MenuItem key={col.id} value={col.id}>
                      {col.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              {/* Priority */}
              <FormControl fullWidth size="small">
                <InputLabel>Priority</InputLabel>
                <Select
                  value={isEditing ? (editedCard.priority ?? card.priority ?? '') : (card.priority ?? '')}
                  label="Priority"
                  onChange={(e) => setEditedCard({ ...editedCard, priority: e.target.value as CardData['priority'] || undefined })}
                  disabled={!isEditing}
                >
                  {priorityOptions.map((opt) => (
                    <MenuItem key={opt.value} value={opt.value}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <FlagIcon fontSize="small" sx={{ color: opt.color }} />
                        {opt.label}
                      </Box>
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              {/* Due Date */}
              <LocalizationProvider dateAdapter={AdapterDateFns}>
                <DateTimePicker
                  label="Due Date"
                  value={
                    isEditing
                      ? (editedCard.due_date ? new Date(editedCard.due_date) : card.due_date ? new Date(card.due_date) : null)
                      : (card.due_date ? new Date(card.due_date) : null)
                  }
                  onChange={(date) => setEditedCard({ ...editedCard, due_date: date?.toISOString() })}
                  disabled={!isEditing}
                  slotProps={{ textField: { size: 'small', fullWidth: true } }}
                />
              </LocalizationProvider>
              
              {/* Estimated Hours */}
              <TextField
                size="small"
                label="Estimated Hours"
                type="number"
                value={isEditing ? (editedCard.estimated_hours ?? card.estimated_hours ?? '') : (card.estimated_hours ?? '')}
                onChange={(e) => setEditedCard({ ...editedCard, estimated_hours: parseFloat(e.target.value) || undefined })}
                disabled={!isEditing}
                inputProps={{ min: 0, step: 0.5 }}
              />
              
              <Divider />
              
              {/* Labels */}
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Labels
                  </Typography>
                  {isEditing && (
                    <IconButton size="small" onClick={(e) => setLabelAnchor(e.currentTarget)}>
                      <AddIcon fontSize="small" />
                    </IconButton>
                  )}
                </Box>
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                  {currentLabels.map((label, idx) => (
                    <Chip
                      key={idx}
                      label={label.name}
                      size="small"
                      sx={{ bgcolor: label.color, color: 'white' }}
                      onDelete={isEditing ? () => handleRemoveLabel(label.name) : undefined}
                    />
                  ))}
                  {currentLabels.length === 0 && (
                    <Typography variant="caption" color="text.secondary">
                      No labels
                    </Typography>
                  )}
                </Box>
              </Box>
              
              {/* Card Color */}
              <Box>
                <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="subtitle2" color="text.secondary">
                    Card Color
                  </Typography>
                  <IconButton size="small" onClick={(e) => setColorAnchor(e.currentTarget)}>
                    <PaletteIcon fontSize="small" />
                  </IconButton>
                </Box>
                <Box
                  onClick={(e) => setColorAnchor(e.currentTarget)}
                  sx={{
                    width: '100%',
                    height: 24,
                    borderRadius: 1,
                    bgcolor: (editedCard.color ?? card.color) || 'background.default',
                    border: '1px solid',
                    borderColor: 'divider',
                    cursor: 'pointer',
                    '&:hover': {
                      borderColor: 'primary.main',
                    },
                  }}
                />
              </Box>
              
              {/* Assignees */}
              <Box>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  Assignees
                </Typography>
                <Autocomplete
                  multiple
                  size="small"
                  options={projectMembers}
                  getOptionLabel={(option) => option.username}
                  value={projectMembers.filter(m => 
                    (editedCard.assignee_ids ?? card.assignee_ids ?? []).includes(m.user_id)
                  )}
                  onChange={async (_, newValue) => {
                    const newAssigneeIds = newValue.map(m => m.user_id);
                    setEditedCard({
                      ...editedCard,
                      assignee_ids: newAssigneeIds
                    });
                    // Auto-save assignee changes
                    try {
                      await kanbanApi.updateCard(card.id, { assignee_ids: newAssigneeIds });
                      setCard({ ...card, assignee_ids: newAssigneeIds });
                      onUpdate();
                    } catch (err) {
                      console.error('Failed to update assignees:', err);
                    }
                  }}
                  loading={loadingMembers}
                  renderOption={(props, option) => (
                    <Box component="li" {...props} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Avatar sx={{ width: 24, height: 24, fontSize: 12 }}>
                        {option.username.charAt(0).toUpperCase()}
                      </Avatar>
                      <Box>
                        <Typography variant="body2">{option.username}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {option.role}
                        </Typography>
                      </Box>
                    </Box>
                  )}
                  renderTags={(value, getTagProps) =>
                    value.map((option, index) => (
                      <Chip
                        {...getTagProps({ index })}
                        key={option.user_id}
                        avatar={
                          <Avatar sx={{ width: 20, height: 20 }}>
                            {option.username.charAt(0).toUpperCase()}
                          </Avatar>
                        }
                        label={option.username}
                        size="small"
                      />
                    ))
                  }
                  renderInput={(params) => (
                    <TextField
                      {...params}
                      placeholder={loadingMembers ? 'Loading...' : 'Add assignees'}
                      variant="outlined"
                    />
                  )}
                />
              </Box>
              
              <Divider />
              
              {/* Metadata */}
              <Box>
                <Typography variant="caption" color="text.secondary" display="block">
                  Created by {card.creator_username || 'Unknown'} on{' '}
                  {format(new Date(card.created_at), 'PPp')}
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block">
                  Last updated {format(new Date(card.updated_at), 'PPp')}
                </Typography>
              </Box>
            </Box>
          </Grid>
        </Grid>
      </DialogContent>
      
      <DialogActions sx={{ justifyContent: 'space-between' }}>
        <Button
          color="error"
          startIcon={<DeleteIcon />}
          onClick={onDelete}
        >
          Delete Card
        </Button>
        <Box>
          {isEditing ? (
            <>
              <Button onClick={() => {
                setIsEditing(false);
                setEditedCard({});
              }}>
                Cancel
              </Button>
              <Button
                variant="contained"
                onClick={handleSave}
                disabled={saving}
                startIcon={<CheckIcon />}
              >
                Save Changes
              </Button>
            </>
          ) : (
            <Button
              variant="contained"
              onClick={() => setIsEditing(true)}
              startIcon={<EditIcon />}
            >
              Edit
            </Button>
          )}
        </Box>
      </DialogActions>
      
      {/* Add Label Menu */}
      <Menu
        anchorEl={labelAnchor}
        open={Boolean(labelAnchor)}
        onClose={() => setLabelAnchor(null)}
      >
        <Box sx={{ p: 2, width: 250 }}>
          <Typography variant="subtitle2" gutterBottom>Add Label</Typography>
          <TextField
            fullWidth
            size="small"
            placeholder="Label name"
            value={newLabelName}
            onChange={(e) => setNewLabelName(e.target.value)}
            sx={{ mb: 1 }}
          />
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
            {labelColors.map((color) => (
              <IconButton
                key={color}
                size="small"
                onClick={() => setNewLabelColor(color)}
                sx={{
                  bgcolor: color,
                  width: 24,
                  height: 24,
                  border: newLabelColor === color ? '2px solid black' : 'none',
                  '&:hover': { bgcolor: color, opacity: 0.8 },
                }}
              />
            ))}
          </Box>
          <Button
            fullWidth
            variant="contained"
            size="small"
            onClick={handleAddLabel}
            disabled={!newLabelName.trim()}
          >
            Add Label
          </Button>
        </Box>
      </Menu>
      
      {/* Card Color Picker Menu */}
      <Menu
        anchorEl={colorAnchor}
        open={Boolean(colorAnchor)}
        onClose={() => setColorAnchor(null)}
      >
        <Box sx={{ p: 2, width: 280 }}>
          <Typography variant="subtitle2" gutterBottom>Card Color</Typography>
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
            {cardColors.map((colorOption) => (
              <Tooltip key={colorOption.value} title={colorOption.label}>
                <IconButton
                  size="small"
                  onClick={async () => {
                    const newColor = colorOption.value || undefined;
                    setEditedCard({ ...editedCard, color: newColor });
                    setColorAnchor(null);
                    // Auto-save color change
                    try {
                      await kanbanApi.updateCard(card.id, { color: newColor });
                      setCard({ ...card, color: newColor });
                      onUpdate();
                    } catch (err) {
                      console.error('Failed to update card color:', err);
                    }
                  }}
                  sx={{
                    bgcolor: colorOption.color || 'background.default',
                    width: 32,
                    height: 32,
                    border: (editedCard.color ?? card.color ?? '') === colorOption.value 
                      ? '2px solid #1976d2' 
                      : '1px solid rgba(255,255,255,0.2)',
                    '&:hover': { 
                      bgcolor: colorOption.color || 'background.default', 
                      opacity: 0.8 
                    },
                  }}
                >
                  {(editedCard.color ?? card.color ?? '') === colorOption.value && (
                    <CheckIcon sx={{ fontSize: 16, color: '#fff' }} />
                  )}
                </IconButton>
              </Tooltip>
            ))}
          </Box>
        </Box>
      </Menu>
    </Dialog>
  );
};

export default CardDetailDialog;
