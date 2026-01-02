/**
 * StatusSelector - Allows users to set their presence status
 */
import React, { useState } from 'react';
import {
  Box,
  Button,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  TextField,
  Divider,
  IconButton,
  Tooltip,
  Typography,
  InputAdornment,
  Select,
  FormControl,
  InputLabel,
} from '@mui/material';
import {
  Circle as CircleIcon,
  Check as CheckIcon,
  Clear as ClearIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { PresenceStatus, PresenceIndicator } from './PresenceIndicator';

interface StatusSelectorProps {
  currentStatus: PresenceStatus;
  customStatus?: string;
  statusEmoji?: string;
  onStatusChange: (status: PresenceStatus, customStatus?: string, statusEmoji?: string, durationMinutes?: number) => void;
  compact?: boolean;
}

const statusOptions: Array<{ status: PresenceStatus; label: string; color: string }> = [
  { status: 'online', label: 'Online', color: '#44b700' },
  { status: 'away', label: 'Away', color: '#ffa000' },
  { status: 'busy', label: 'Busy', color: '#f44336' },
  { status: 'dnd', label: 'Do Not Disturb', color: '#d32f2f' },
  { status: 'offline', label: 'Appear Offline', color: '#bdbdbd' },
];

const quickEmojis = ['💻', '📞', '🍽️', '🏠', '🎮', '📚', '🎵', '✈️', '🤒', '🔕'];

const durationOptions = [
  { label: 'Don\'t clear', value: 0 },
  { label: '30 minutes', value: 30 },
  { label: '1 hour', value: 60 },
  { label: '2 hours', value: 120 },
  { label: '4 hours', value: 240 },
  { label: 'Today', value: 'today' },
];

export const StatusSelector: React.FC<StatusSelectorProps> = ({
  currentStatus,
  customStatus,
  statusEmoji,
  onStatusChange,
  compact = false,
}) => {
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [showCustom, setShowCustom] = useState(false);
  const [newCustomStatus, setNewCustomStatus] = useState(customStatus || '');
  const [newEmoji, setNewEmoji] = useState(statusEmoji || '');
  const [duration, setDuration] = useState<number | string>(0);
  
  const open = Boolean(anchorEl);
  
  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
    setNewCustomStatus(customStatus || '');
    setNewEmoji(statusEmoji || '');
    setShowCustom(false);
  };
  
  const handleClose = () => {
    setAnchorEl(null);
    setShowCustom(false);
  };
  
  const handleStatusSelect = (status: PresenceStatus) => {
    onStatusChange(status);
    handleClose();
  };
  
  const handleCustomStatusSave = () => {
    // Calculate duration in minutes
    let durationMinutes: number | undefined;
    if (duration === 'today') {
      const now = new Date();
      const endOfDay = new Date(now);
      endOfDay.setHours(23, 59, 59, 999);
      durationMinutes = Math.round((endOfDay.getTime() - now.getTime()) / 60000);
    } else if (typeof duration === 'number' && duration > 0) {
      durationMinutes = duration;
    }
    
    onStatusChange(currentStatus, newCustomStatus || undefined, newEmoji || undefined, durationMinutes);
    handleClose();
  };
  
  const handleClearCustomStatus = () => {
    onStatusChange(currentStatus, undefined, undefined);
    setNewCustomStatus('');
    setNewEmoji('');
  };
  
  const currentOption = statusOptions.find(opt => opt.status === currentStatus);
  
  if (compact) {
    return (
      <>
        <Tooltip title="Set status">
          <IconButton onClick={handleClick} size="small">
            <PresenceIndicator status={currentStatus} size="small" showTooltip={false} />
          </IconButton>
        </Tooltip>
        
        <Menu
          anchorEl={anchorEl}
          open={open}
          onClose={handleClose}
          PaperProps={{ sx: { width: 280, maxHeight: 400 } }}
        >
          {statusOptions.map((option) => (
            <MenuItem
              key={option.status}
              onClick={() => handleStatusSelect(option.status)}
              selected={currentStatus === option.status}
            >
              <ListItemIcon>
                <CircleIcon sx={{ color: option.color, fontSize: 12 }} />
              </ListItemIcon>
              <ListItemText>{option.label}</ListItemText>
              {currentStatus === option.status && <CheckIcon fontSize="small" />}
            </MenuItem>
          ))}
          
          <Divider />
          
          <MenuItem onClick={() => setShowCustom(!showCustom)}>
            <ListItemIcon>
              <ScheduleIcon fontSize="small" />
            </ListItemIcon>
            <ListItemText>Set custom status</ListItemText>
          </MenuItem>
          
          {showCustom && (
            <Box sx={{ p: 2 }}>
              <TextField
                fullWidth
                size="small"
                placeholder="What's your status?"
                value={newCustomStatus}
                onChange={(e) => setNewCustomStatus(e.target.value)}
                InputProps={{
                  startAdornment: newEmoji ? (
                    <InputAdornment position="start">{newEmoji}</InputAdornment>
                  ) : undefined,
                }}
                sx={{ mb: 1 }}
              />
              
              <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
                {quickEmojis.map((emoji) => (
                  <IconButton
                    key={emoji}
                    size="small"
                    onClick={() => setNewEmoji(newEmoji === emoji ? '' : emoji)}
                    sx={{
                      bgcolor: newEmoji === emoji ? 'action.selected' : 'transparent',
                      fontSize: '1rem',
                      p: 0.5,
                    }}
                  >
                    {emoji}
                  </IconButton>
                ))}
              </Box>
              
              <FormControl fullWidth size="small" sx={{ mb: 1 }}>
                <InputLabel>Clear after</InputLabel>
                <Select
                  value={duration}
                  label="Clear after"
                  onChange={(e) => setDuration(e.target.value)}
                >
                  {durationOptions.map((opt) => (
                    <MenuItem key={opt.value} value={opt.value}>
                      {opt.label}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
              
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Button
                  variant="contained"
                  size="small"
                  onClick={handleCustomStatusSave}
                  disabled={!newCustomStatus.trim()}
                >
                  Save
                </Button>
                {customStatus && (
                  <Button
                    variant="outlined"
                    size="small"
                    color="error"
                    onClick={handleClearCustomStatus}
                    startIcon={<ClearIcon />}
                  >
                    Clear
                  </Button>
                )}
              </Box>
            </Box>
          )}
        </Menu>
      </>
    );
  }
  
  // Full button version
  return (
    <>
      <Button
        variant="outlined"
        onClick={handleClick}
        startIcon={
          <PresenceIndicator status={currentStatus} size="small" showTooltip={false} />
        }
        sx={{ textTransform: 'none' }}
      >
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
          <Typography variant="body2" fontWeight={500}>
            {currentOption?.label}
          </Typography>
          {customStatus && (
            <Typography variant="caption" color="text.secondary" sx={{ maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {statusEmoji && `${statusEmoji} `}{customStatus}
            </Typography>
          )}
        </Box>
      </Button>
      
      <Menu
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        PaperProps={{ sx: { width: 300, maxHeight: 450 } }}
      >
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="subtitle2" color="text.secondary">
            Set your status
          </Typography>
        </Box>
        
        {statusOptions.map((option) => (
          <MenuItem
            key={option.status}
            onClick={() => handleStatusSelect(option.status)}
            selected={currentStatus === option.status}
          >
            <ListItemIcon>
              <CircleIcon sx={{ color: option.color, fontSize: 14 }} />
            </ListItemIcon>
            <ListItemText>{option.label}</ListItemText>
            {currentStatus === option.status && <CheckIcon fontSize="small" color="primary" />}
          </MenuItem>
        ))}
        
        <Divider sx={{ my: 1 }} />
        
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Custom status
          </Typography>
          
          <TextField
            fullWidth
            size="small"
            placeholder="What's happening?"
            value={newCustomStatus}
            onChange={(e) => setNewCustomStatus(e.target.value)}
            InputProps={{
              startAdornment: newEmoji ? (
                <InputAdornment position="start">{newEmoji}</InputAdornment>
              ) : undefined,
            }}
            sx={{ mb: 1 }}
          />
          
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1.5 }}>
            {quickEmojis.map((emoji) => (
              <IconButton
                key={emoji}
                size="small"
                onClick={() => setNewEmoji(newEmoji === emoji ? '' : emoji)}
                sx={{
                  bgcolor: newEmoji === emoji ? 'action.selected' : 'transparent',
                  fontSize: '1rem',
                  p: 0.5,
                }}
              >
                {emoji}
              </IconButton>
            ))}
          </Box>
          
          <FormControl fullWidth size="small" sx={{ mb: 1.5 }}>
            <InputLabel>Clear after</InputLabel>
            <Select
              value={duration}
              label="Clear after"
              onChange={(e) => setDuration(e.target.value)}
            >
              {durationOptions.map((opt) => (
                <MenuItem key={opt.value} value={opt.value}>
                  {opt.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              variant="contained"
              size="small"
              fullWidth
              onClick={handleCustomStatusSave}
            >
              {newCustomStatus.trim() ? 'Set Status' : 'Save'}
            </Button>
            {customStatus && (
              <Button
                variant="outlined"
                size="small"
                color="error"
                onClick={handleClearCustomStatus}
              >
                Clear
              </Button>
            )}
          </Box>
        </Box>
      </Menu>
    </>
  );
};

export default StatusSelector;
