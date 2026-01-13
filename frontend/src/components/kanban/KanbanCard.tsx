/**
 * KanbanCard - Individual card component in the Kanban board
 */
import React from 'react';
import {
  Card,
  CardContent,
  Typography,
  Box,
  Chip,
  Avatar,
  AvatarGroup,
  Tooltip,
  IconButton,
  LinearProgress,
} from '@mui/material';
import {
  Flag as FlagIcon,
  Schedule as ScheduleIcon,
  CheckCircle as CheckCircleIcon,
  Comment as CommentIcon,
  AttachFile as AttachmentIcon,
  BugReport as BugIcon,
  CheckBox as ChecklistIcon,
} from '@mui/icons-material';
import { formatDistanceToNow, isPast, format } from 'date-fns';
import { KanbanCard as KanbanCardType, KanbanCardLabel, KanbanChecklistItem } from '../../api/client';

// Re-export types for convenience
export type CardLabel = KanbanCardLabel;
export type ChecklistItem = KanbanChecklistItem;
export interface AssigneeInfo {
  user_id: number;
  username: string;
  first_name?: string;
  avatar_url?: string;
}
export type CardData = KanbanCardType;

interface KanbanCardProps {
  card: CardData;
  onClick?: () => void;
  isDragging?: boolean;
  onFindingClick?: (findingId: number) => void;
}

const priorityColors: Record<string, string> = {
  low: '#4caf50',
  medium: '#ff9800',
  high: '#f44336',
  critical: '#d32f2f',
};

const priorityLabels: Record<string, string> = {
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
};

export const KanbanCard: React.FC<KanbanCardProps> = ({
  card,
  onClick,
  isDragging = false,
  onFindingClick,
}) => {
  const isOverdue = card.due_date && isPast(new Date(card.due_date)) && !card.completed_at;
  const isCompleted = Boolean(card.completed_at);
  
  // Calculate checklist progress
  const checklistProgress = card.checklist?.length
    ? (card.checklist.filter(item => item.completed).length / card.checklist.length) * 100
    : null;
  
  return (
    <Card
      sx={{
        mb: 1,
        cursor: 'pointer',
        boxShadow: isDragging ? 4 : 1,
        transform: isDragging ? 'rotate(3deg)' : 'none',
        transition: 'box-shadow 0.2s, transform 0.2s',
        '&:hover': {
          boxShadow: 3,
        },
        opacity: isCompleted ? 0.7 : 1,
        borderLeft: card.priority ? `4px solid ${priorityColors[card.priority]}` : undefined,
        bgcolor: card.color || 'background.paper',
      }}
      onClick={onClick}
    >
      <CardContent sx={{ p: 1.5, '&:last-child': { pb: 1.5 } }}>
        {/* Labels */}
        {card.labels && card.labels.length > 0 && (
          <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', mb: 1 }}>
            {card.labels.slice(0, 3).map((label, idx) => (
              <Chip
                key={idx}
                label={label.name}
                size="small"
                sx={{
                  height: 20,
                  fontSize: '0.65rem',
                  bgcolor: label.color,
                  color: 'white',
                }}
              />
            ))}
            {card.labels.length > 3 && (
              <Chip
                label={`+${card.labels.length - 3}`}
                size="small"
                sx={{ height: 20, fontSize: '0.65rem' }}
              />
            )}
          </Box>
        )}
        
        {/* Title */}
        <Typography
          variant="body2"
          fontWeight={500}
          sx={{
            mb: 1,
            textDecoration: isCompleted ? 'line-through' : 'none',
            color: isCompleted ? 'text.secondary' : 'text.primary',
          }}
        >
          {card.title}
        </Typography>
        
        {/* Finding Badge */}
        {card.finding_id && (
          <Chip
            icon={<BugIcon fontSize="small" />}
            label={`Finding #${card.finding_id}`}
            size="small"
            color="error"
            variant="outlined"
            onClick={(e) => {
              e.stopPropagation();
              onFindingClick?.(card.finding_id!);
            }}
            sx={{ mb: 1, height: 22, fontSize: '0.7rem' }}
          />
        )}
        
        {/* Checklist Progress */}
        {checklistProgress !== null && (
          <Box sx={{ mb: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 0.5 }}>
              <ChecklistIcon fontSize="small" sx={{ opacity: 0.6, fontSize: 16 }} />
              <Typography variant="caption" color="text.secondary">
                {card.checklist!.filter(i => i.completed).length}/{card.checklist!.length}
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={checklistProgress}
              sx={{ height: 4, borderRadius: 2 }}
              color={checklistProgress === 100 ? 'success' : 'primary'}
            />
          </Box>
        )}
        
        {/* Footer */}
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: 0.5,
          }}
        >
          {/* Left side - Icons */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {/* Priority */}
            {card.priority && (
              <Tooltip title={`${priorityLabels[card.priority]} Priority`}>
                <FlagIcon
                  fontSize="small"
                  sx={{
                    color: priorityColors[card.priority],
                    fontSize: 16,
                  }}
                />
              </Tooltip>
            )}
            
            {/* Due Date */}
            {card.due_date && (
              <Tooltip title={`Due: ${format(new Date(card.due_date), 'PPp')}`}>
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.25,
                    color: isOverdue ? 'error.main' : isCompleted ? 'success.main' : 'text.secondary',
                  }}
                >
                  {isCompleted ? (
                    <CheckCircleIcon sx={{ fontSize: 14 }} />
                  ) : (
                    <ScheduleIcon sx={{ fontSize: 14 }} />
                  )}
                  <Typography variant="caption" fontSize="0.65rem">
                    {formatDistanceToNow(new Date(card.due_date), { addSuffix: true })}
                  </Typography>
                </Box>
              </Tooltip>
            )}
            
            {/* Comments */}
            {(card.comment_count || 0) > 0 && (
              <Tooltip title={`${card.comment_count} comments`}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25, color: 'text.secondary' }}>
                  <CommentIcon sx={{ fontSize: 14 }} />
                  <Typography variant="caption" fontSize="0.65rem">
                    {card.comment_count}
                  </Typography>
                </Box>
              </Tooltip>
            )}
            
            {/* Attachments */}
            {(card.attachment_count || 0) > 0 && (
              <Tooltip title={`${card.attachment_count} attachments`}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.25, color: 'text.secondary' }}>
                  <AttachmentIcon sx={{ fontSize: 14 }} />
                  <Typography variant="caption" fontSize="0.65rem">
                    {card.attachment_count}
                  </Typography>
                </Box>
              </Tooltip>
            )}
          </Box>
          
          {/* Right side - Assignees */}
          {card.assignees && card.assignees.length > 0 && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <AvatarGroup max={2} sx={{ '& .MuiAvatar-root': { width: 20, height: 20, fontSize: 10 } }}>
                {card.assignees.map((assignee) => (
                  <Tooltip key={assignee.user_id} title={assignee.first_name || assignee.username}>
                    <Avatar
                      alt={assignee.username}
                      src={assignee.avatar_url}
                    >
                      {(assignee.first_name || assignee.username).charAt(0).toUpperCase()}
                    </Avatar>
                  </Tooltip>
                ))}
              </AvatarGroup>
              <Typography variant="caption" color="text.secondary" sx={{ fontSize: '0.65rem', maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {card.assignees.map(a => a.first_name || a.username).join(', ')}
              </Typography>
            </Box>
          )}
        </Box>
      </CardContent>
    </Card>
  );
};

export default KanbanCard;
