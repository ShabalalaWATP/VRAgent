/**
 * AddCardDialog - Dialog for creating a new Kanban card with full details
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
  Divider,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Tooltip,
  Menu,
  Grid,
  Autocomplete,
} from '@mui/material';
import {
  Close as CloseIcon,
  Flag as FlagIcon,
  Add as AddIcon,
  Palette as PaletteIcon,
  Check as CheckIcon,
} from '@mui/icons-material';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns';
import { CardLabel } from './KanbanCard';
import { api, ProjectCollaborator } from '../../api/client';

interface AddCardDialogProps {
  open: boolean;
  columnId: number;
  columnName: string;
  projectId: number;
  onClose: () => void;
  onAdd: (cardData: NewCardData) => void;
}

export interface NewCardData {
  title: string;
  description?: string;
  priority?: string;
  labels?: CardLabel[];
  due_date?: string;
  assignee_ids?: number[];
  color?: string;
}

interface ProjectMember {
  user_id: number;
  username: string;
  email?: string;
  role: string;
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

export const AddCardDialog: React.FC<AddCardDialogProps> = ({
  open,
  columnId,
  columnName,
  projectId,
  onClose,
  onAdd,
}) => {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('');
  const [labels, setLabels] = useState<CardLabel[]>([]);
  const [dueDate, setDueDate] = useState<Date | null>(null);
  const [assigneeIds, setAssigneeIds] = useState<number[]>([]);
  const [color, setColor] = useState('');
  const [saving, setSaving] = useState(false);
  
  // Project members for assignee selection
  const [projectMembers, setProjectMembers] = useState<ProjectMember[]>([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  
  // Label menu
  const [labelAnchor, setLabelAnchor] = useState<null | HTMLElement>(null);
  const [newLabelName, setNewLabelName] = useState('');
  const [newLabelColor, setNewLabelColor] = useState(labelColors[0]);
  
  // Color picker
  const [colorAnchor, setColorAnchor] = useState<null | HTMLElement>(null);
  
  useEffect(() => {
    if (open) {
      loadProjectMembers();
      // Reset form
      setTitle('');
      setDescription('');
      setPriority('');
      setLabels([]);
      setDueDate(null);
      setAssigneeIds([]);
      setColor('');
    }
  }, [open, projectId]);
  
  const loadProjectMembers = async () => {
    try {
      setLoadingMembers(true);
      const collaborators = await api.getProjectCollaborators(projectId);
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
  
  const handleAdd = async () => {
    if (!title.trim()) return;
    
    setSaving(true);
    try {
      const cardData: NewCardData = {
        title: title.trim(),
        description: description.trim() || undefined,
        priority: priority || undefined,
        labels: labels.length > 0 ? labels : undefined,
        due_date: dueDate?.toISOString(),
        assignee_ids: assigneeIds.length > 0 ? assigneeIds : undefined,
        color: color || undefined,
      };
      
      onAdd(cardData);
      onClose();
    } catch (err) {
      console.error('Failed to create card:', err);
    } finally {
      setSaving(false);
    }
  };
  
  const handleAddLabel = () => {
    if (!newLabelName.trim()) return;
    
    const newLabel: CardLabel = {
      name: newLabelName.trim(),
      color: newLabelColor,
    };
    
    setLabels([...labels, newLabel]);
    setNewLabelName('');
    setLabelAnchor(null);
  };
  
  const handleRemoveLabel = (labelName: string) => {
    setLabels(labels.filter(l => l.name !== labelName));
  };
  
  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1, pr: 6 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          Add Card to "{columnName}"
        </Typography>
        <IconButton
          onClick={onClose}
          sx={{ position: 'absolute', right: 8, top: 8 }}
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      
      <DialogContent dividers>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {/* Title */}
          <TextField
            fullWidth
            label="Title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Enter card title"
            autoFocus
            required
          />
          
          {/* Description */}
          <TextField
            fullWidth
            multiline
            rows={3}
            label="Description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Add a more detailed description..."
          />
          
          <Grid container spacing={2}>
            {/* Priority */}
            <Grid item xs={6}>
              <FormControl fullWidth size="small">
                <InputLabel>Priority</InputLabel>
                <Select
                  value={priority}
                  label="Priority"
                  onChange={(e) => setPriority(e.target.value)}
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
            </Grid>
            
            {/* Due Date */}
            <Grid item xs={6}>
              <LocalizationProvider dateAdapter={AdapterDateFns}>
                <DateTimePicker
                  label="Due Date"
                  value={dueDate}
                  onChange={(date) => setDueDate(date)}
                  slotProps={{ textField: { size: 'small', fullWidth: true } }}
                />
              </LocalizationProvider>
            </Grid>
          </Grid>
          
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
              value={projectMembers.filter(m => assigneeIds.includes(m.user_id))}
              onChange={(_, newValue) => {
                setAssigneeIds(newValue.map(m => m.user_id));
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
                  placeholder={loadingMembers ? 'Loading...' : 'Select assignees'}
                  variant="outlined"
                />
              )}
            />
          </Box>
          
          <Divider />
          
          {/* Labels */}
          <Box>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="subtitle2" color="text.secondary">
                Labels
              </Typography>
              <IconButton size="small" onClick={(e) => setLabelAnchor(e.currentTarget)}>
                <AddIcon fontSize="small" />
              </IconButton>
            </Box>
            <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
              {labels.map((label, idx) => (
                <Chip
                  key={idx}
                  label={label.name}
                  size="small"
                  sx={{ bgcolor: label.color, color: 'white' }}
                  onDelete={() => handleRemoveLabel(label.name)}
                />
              ))}
              {labels.length === 0 && (
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
                bgcolor: color || 'background.default',
                border: '1px solid',
                borderColor: 'divider',
                cursor: 'pointer',
                '&:hover': {
                  borderColor: 'primary.main',
                },
              }}
            />
          </Box>
        </Box>
      </DialogContent>
      
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          onClick={handleAdd}
          disabled={!title.trim() || saving}
        >
          Add Card
        </Button>
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
            {labelColors.map((labelColor) => (
              <IconButton
                key={labelColor}
                size="small"
                onClick={() => setNewLabelColor(labelColor)}
                sx={{
                  bgcolor: labelColor,
                  width: 24,
                  height: 24,
                  border: newLabelColor === labelColor ? '2px solid white' : 'none',
                  '&:hover': { bgcolor: labelColor, opacity: 0.8 },
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
                  onClick={() => {
                    setColor(colorOption.value);
                    setColorAnchor(null);
                  }}
                  sx={{
                    bgcolor: colorOption.color || 'background.default',
                    width: 32,
                    height: 32,
                    border: color === colorOption.value 
                      ? '2px solid #1976d2' 
                      : '1px solid rgba(255,255,255,0.2)',
                    '&:hover': { 
                      bgcolor: colorOption.color || 'background.default', 
                      opacity: 0.8 
                    },
                  }}
                >
                  {color === colorOption.value && (
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

export default AddCardDialog;
