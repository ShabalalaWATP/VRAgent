/**
 * Shared animation keyframes for consistent UI animations across the app.
 * Import these instead of defining duplicate keyframes in each component.
 */

import { keyframes } from '@mui/material';

/**
 * Pulse animation - opacity fades in/out
 * Use for attention-grabbing elements, loading indicators
 */
export const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

/**
 * Shimmer animation - sliding gradient effect
 * Use for skeleton loaders, loading states
 */
export const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

/**
 * Float animation - gentle vertical bob
 * Use for decorative elements, icons, avatars
 */
export const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-3px); }
`;

/**
 * Float slow - slower, more subtle float
 * Use for background decorative elements
 */
export const floatSlow = keyframes`
  0%, 100% { transform: translateY(0) rotate(0deg); }
  50% { transform: translateY(-10px) rotate(2deg); }
`;

/**
 * Pulse glow - glowing effect with box-shadow
 * Use for active/running states, important alerts
 */
export const pulseGlow = keyframes`
  0%, 100% {
    opacity: 1;
    box-shadow: 0 0 15px rgba(99, 102, 241, 0.5);
  }
  50% {
    opacity: 0.9;
    box-shadow: 0 0 25px rgba(99, 102, 241, 0.8);
  }
`;

/**
 * Lock pulse - secure/lock icon animation
 * Use for SSL/security indicators
 */
export const lockPulse = keyframes`
  0%, 100% { 
    transform: scale(1);
    filter: drop-shadow(0 0 5px rgba(34, 211, 238, 0.3));
  }
  50% { 
    transform: scale(1.05);
    filter: drop-shadow(0 0 10px rgba(34, 211, 238, 0.5));
  }
`;

/**
 * Fade in animation
 * Use for elements appearing on screen
 */
export const fadeIn = keyframes`
  from { opacity: 0; }
  to { opacity: 1; }
`;

/**
 * Fade in and slide up
 * Use for list items, cards appearing
 */
export const fadeInUp = keyframes`
  from {
    opacity: 0;
    transform: translateY(20px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
`;

/**
 * Spin animation
 * Use for loading spinners
 */
export const spin = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`;

/**
 * Bounce animation
 * Use for attention-grabbing notifications
 */
export const bounce = keyframes`
  0%, 100% {
    transform: translateY(0);
  }
  50% {
    transform: translateY(-5px);
  }
`;

/**
 * Scale in animation
 * Use for modals, popups appearing
 */
export const scaleIn = keyframes`
  from {
    opacity: 0;
    transform: scale(0.9);
  }
  to {
    opacity: 1;
    transform: scale(1);
  }
`;
