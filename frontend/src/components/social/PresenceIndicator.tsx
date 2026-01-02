/**
 * PresenceIndicator - Shows user's online status with a colored badge
 */
import React from 'react';
import { Badge, Tooltip, Box } from '@mui/material';
import { styled } from '@mui/material/styles';

export type PresenceStatus = 'online' | 'away' | 'busy' | 'dnd' | 'offline';

interface PresenceIndicatorProps {
  status: PresenceStatus;
  customStatus?: string;
  statusEmoji?: string;
  showTooltip?: boolean;
  size?: 'small' | 'medium' | 'large';
  children?: React.ReactNode;
}

const statusColors: Record<PresenceStatus, string> = {
  online: '#44b700',
  away: '#ffa000',
  busy: '#f44336',
  dnd: '#d32f2f',
  offline: '#bdbdbd',
};

const statusLabels: Record<PresenceStatus, string> = {
  online: 'Online',
  away: 'Away',
  busy: 'Busy',
  dnd: 'Do Not Disturb',
  offline: 'Offline',
};

const StyledBadge = styled(Badge, {
  shouldForwardProp: (prop) => prop !== 'statusColor' && prop !== 'badgeSize',
})<{ statusColor: string; badgeSize: number }>(({ theme, statusColor, badgeSize }) => ({
  '& .MuiBadge-badge': {
    backgroundColor: statusColor,
    color: statusColor,
    boxShadow: `0 0 0 2px ${theme.palette.background.paper}`,
    width: badgeSize,
    height: badgeSize,
    borderRadius: '50%',
    '&::after': {
      position: 'absolute',
      top: 0,
      left: 0,
      width: '100%',
      height: '100%',
      borderRadius: '50%',
      animation: statusColor === statusColors.online ? 'ripple 1.2s infinite ease-in-out' : 'none',
      border: '1px solid currentColor',
      content: '""',
    },
  },
  '@keyframes ripple': {
    '0%': {
      transform: 'scale(.8)',
      opacity: 1,
    },
    '100%': {
      transform: 'scale(2.4)',
      opacity: 0,
    },
  },
}));

// Standalone dot indicator (no children)
const StatusDot = styled(Box, {
  shouldForwardProp: (prop) => prop !== 'statusColor' && prop !== 'dotSize',
})<{ statusColor: string; dotSize: number }>(({ statusColor, dotSize }) => ({
  width: dotSize,
  height: dotSize,
  borderRadius: '50%',
  backgroundColor: statusColor,
  display: 'inline-block',
  flexShrink: 0,
}));

export const PresenceIndicator: React.FC<PresenceIndicatorProps> = ({
  status,
  customStatus,
  statusEmoji,
  showTooltip = true,
  size = 'medium',
  children,
}) => {
  const badgeSizes = {
    small: 8,
    medium: 12,
    large: 16,
  };
  
  const badgeSize = badgeSizes[size];
  const statusColor = statusColors[status] || statusColors.offline;
  
  const tooltipContent = (
    <Box sx={{ textAlign: 'center' }}>
      <Box sx={{ fontWeight: 500 }}>
        {statusEmoji && <span style={{ marginRight: 4 }}>{statusEmoji}</span>}
        {statusLabels[status]}
      </Box>
      {customStatus && (
        <Box sx={{ fontSize: '0.75rem', opacity: 0.8 }}>
          {customStatus}
        </Box>
      )}
    </Box>
  );
  
  // If no children, render standalone dot
  if (!children) {
    const dot = (
      <StatusDot 
        statusColor={statusColor} 
        dotSize={badgeSize} 
      />
    );
    
    if (showTooltip) {
      return (
        <Tooltip title={tooltipContent} arrow placement="top">
          {dot}
        </Tooltip>
      );
    }
    return dot;
  }
  
  // Render badge around children (usually avatar)
  const badge = (
    <StyledBadge
      overlap="circular"
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      variant="dot"
      statusColor={statusColor}
      badgeSize={badgeSize}
    >
      {children}
    </StyledBadge>
  );
  
  if (showTooltip) {
    return (
      <Tooltip title={tooltipContent} arrow placement="top">
        {badge}
      </Tooltip>
    );
  }
  
  return badge;
};

export default PresenceIndicator;
