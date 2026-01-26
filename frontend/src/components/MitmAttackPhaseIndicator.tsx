import React from 'react';
import {
  Box,
  Paper,
  Typography,
  Stepper,
  Step,
  StepLabel,
  StepConnector,
  Chip,
  LinearProgress,
  Tooltip,
  IconButton,
  Collapse,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Badge,
} from '@mui/material';
import { styled } from '@mui/material/styles';
import {
  Search as ReconIcon,
  VpnKey as AccessIcon,
  BugReport as ExploitIcon,
  Storage as PersistIcon,
  TrendingUp as EscalateIcon,
  CloudDownload as ExfilIcon,
  CheckCircle as CheckIcon,
  RadioButtonUnchecked as PendingIcon,
  PlayCircle as ActiveIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';

// Custom connector styling
const ColorlibConnector = styled(StepConnector)(({ theme }) => ({
  '& .MuiStepConnector-line': {
    height: 3,
    border: 0,
    backgroundColor: theme.palette.mode === 'dark' ? theme.palette.grey[800] : '#eaeaf0',
    borderRadius: 1,
  },
  '&.Mui-active .MuiStepConnector-line': {
    backgroundImage: 'linear-gradient(95deg, #f44336 0%, #ff9800 50%, #4caf50 100%)',
  },
  '&.Mui-completed .MuiStepConnector-line': {
    backgroundImage: 'linear-gradient(95deg, #4caf50 0%, #8bc34a 100%)',
  },
}));

// Custom step icon
const ColorlibStepIconRoot = styled('div')<{
  ownerState: { completed?: boolean; active?: boolean };
}>(({ theme, ownerState }) => ({
  backgroundColor: theme.palette.mode === 'dark' ? theme.palette.grey[700] : '#ccc',
  zIndex: 1,
  color: '#fff',
  width: 50,
  height: 50,
  display: 'flex',
  borderRadius: '50%',
  justifyContent: 'center',
  alignItems: 'center',
  ...(ownerState.active && {
    backgroundImage: 'linear-gradient(136deg, #f44336 0%, #ff5722 50%, #ff9800 100%)',
    boxShadow: '0 4px 10px 0 rgba(244,67,54,.25)',
    animation: 'pulse 2s infinite',
  }),
  ...(ownerState.completed && {
    backgroundImage: 'linear-gradient(136deg, #4caf50 0%, #8bc34a 100%)',
  }),
  '@keyframes pulse': {
    '0%': {
      boxShadow: '0 0 0 0 rgba(244,67,54, 0.4)',
    },
    '70%': {
      boxShadow: '0 0 0 10px rgba(244,67,54, 0)',
    },
    '100%': {
      boxShadow: '0 0 0 0 rgba(244,67,54, 0)',
    },
  },
}));

interface PhaseData {
  phase: string;
  name: string;
  description: string;
  is_current: boolean;
  is_complete: boolean;
  goals: string[];
  goals_achieved: string[];
  entered_at: string | null;
  completed_at: string | null;
}

interface PhaseProgress {
  phase: string;
  goals_total: number;
  goals_achieved: number;
  goals_achieved_list: string[];
  tools_executed: number;
  credentials_captured: number;
  sessions_hijacked: number;
  injections_successful: number;
  findings_generated: number;
  is_complete: boolean;
}

interface MitmAttackPhaseIndicatorProps {
  phases: PhaseData[];
  currentPhase: PhaseData | null;
  progress: PhaseProgress | null;
  onPhaseClick?: (phase: string) => void;
}

const phaseIcons: Record<string, React.ReactElement> = {
  reconnaissance: <ReconIcon />,
  initial_access: <AccessIcon />,
  exploitation: <ExploitIcon />,
  persistence: <PersistIcon />,
  escalation: <EscalateIcon />,
  exfiltration: <ExfilIcon />,
};

const phaseColors: Record<string, string> = {
  reconnaissance: '#2196f3',
  initial_access: '#ff9800',
  exploitation: '#f44336',
  persistence: '#9c27b0',
  escalation: '#e91e63',
  exfiltration: '#4caf50',
};

function ColorlibStepIcon(props: {
  active: boolean;
  completed: boolean;
  icon: React.ReactNode;
  phase: string;
}) {
  const { active, completed, phase } = props;

  return (
    <ColorlibStepIconRoot ownerState={{ completed, active }}>
      {phaseIcons[phase] || <SecurityIcon />}
    </ColorlibStepIconRoot>
  );
}

const MitmAttackPhaseIndicator: React.FC<MitmAttackPhaseIndicatorProps> = ({
  phases,
  currentPhase,
  progress,
  onPhaseClick,
}) => {
  const [expanded, setExpanded] = React.useState(true);

  const activeStep = phases.findIndex((p) => p.is_current);
  const completedSteps = phases.filter((p) => p.is_complete).length;

  const getStepStatus = (phase: PhaseData, index: number) => {
    if (phase.is_current) return 'active';
    if (phase.is_complete) return 'completed';
    return 'pending';
  };

  return (
    <Paper
      elevation={3}
      sx={{
        p: 2,
        mb: 2,
        background: 'linear-gradient(135deg, rgba(33,33,33,0.95) 0%, rgba(66,66,66,0.95) 100%)',
        border: '1px solid rgba(244,67,54,0.3)',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon sx={{ color: '#f44336' }} />
          <Typography variant="h6" sx={{ color: '#fff' }}>
            Attack Phase Progress
          </Typography>
          <Chip
            size="small"
            label={`${completedSteps}/${phases.length} phases`}
            color={completedSteps === phases.length ? 'success' : 'warning'}
            sx={{ ml: 1 }}
          />
        </Box>
        <IconButton onClick={() => setExpanded(!expanded)} sx={{ color: '#fff' }}>
          {expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
      </Box>

      <Collapse in={expanded}>
        {/* Phase Stepper */}
        <Stepper
          activeStep={activeStep}
          connector={<ColorlibConnector />}
          alternativeLabel
          sx={{ mb: 3 }}
        >
          {phases.map((phase, index) => (
            <Step key={phase.phase} completed={phase.is_complete}>
              <StepLabel
                StepIconComponent={(props) => (
                  <Tooltip title={phase.description} arrow>
                    <span>
                      <ColorlibStepIcon
                        {...props}
                        active={phase.is_current}
                        completed={phase.is_complete}
                        phase={phase.phase}
                      />
                    </span>
                  </Tooltip>
                )}
                onClick={() => onPhaseClick?.(phase.phase)}
                sx={{
                  cursor: onPhaseClick ? 'pointer' : 'default',
                  '& .MuiStepLabel-label': {
                    color: phase.is_current ? '#f44336' : phase.is_complete ? '#4caf50' : '#999',
                    fontWeight: phase.is_current ? 'bold' : 'normal',
                    fontSize: '0.85rem',
                  },
                }}
              >
                {phase.name}
              </StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Current Phase Details */}
        {currentPhase && progress && (
          <Box
            sx={{
              p: 2,
              borderRadius: 1,
              bgcolor: 'rgba(244,67,54,0.1)',
              border: '1px solid rgba(244,67,54,0.3)',
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="subtitle1" sx={{ color: '#fff', fontWeight: 'bold' }}>
                Current: {currentPhase.name}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Chip
                  size="small"
                  icon={<CheckIcon />}
                  label={`${progress.goals_achieved}/${progress.goals_total} goals`}
                  color={progress.goals_achieved === progress.goals_total ? 'success' : 'default'}
                />
                {progress.credentials_captured > 0 && (
                  <Badge badgeContent={progress.credentials_captured} color="error">
                    <Chip size="small" label="Creds" color="error" />
                  </Badge>
                )}
                {progress.findings_generated > 0 && (
                  <Chip size="small" label={`${progress.findings_generated} findings`} color="info" />
                )}
              </Box>
            </Box>

            <Typography variant="body2" sx={{ color: '#aaa', mb: 2 }}>
              {currentPhase.description}
            </Typography>

            {/* Progress Bar */}
            <Box sx={{ mb: 2 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" sx={{ color: '#888' }}>
                  Phase Progress
                </Typography>
                <Typography variant="caption" sx={{ color: '#888' }}>
                  {Math.round((progress.goals_achieved / Math.max(1, progress.goals_total)) * 100)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={(progress.goals_achieved / Math.max(1, progress.goals_total)) * 100}
                sx={{
                  height: 8,
                  borderRadius: 4,
                  bgcolor: 'rgba(255,255,255,0.1)',
                  '& .MuiLinearProgress-bar': {
                    borderRadius: 4,
                    backgroundImage: 'linear-gradient(90deg, #f44336, #ff9800)',
                  },
                }}
              />
            </Box>

            {/* Goals List */}
            <Typography variant="caption" sx={{ color: '#888', display: 'block', mb: 1 }}>
              Goals:
            </Typography>
            <List dense sx={{ py: 0 }}>
              {currentPhase.goals.map((goal, idx) => {
                const achieved = progress.goals_achieved_list.includes(goal);
                return (
                  <ListItem key={idx} sx={{ py: 0.25, px: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {achieved ? (
                        <CheckIcon sx={{ fontSize: 16, color: '#4caf50' }} />
                      ) : (
                        <PendingIcon sx={{ fontSize: 16, color: '#666' }} />
                      )}
                    </ListItemIcon>
                    <ListItemText
                      primary={goal}
                      primaryTypographyProps={{
                        variant: 'body2',
                        sx: {
                          color: achieved ? '#4caf50' : '#999',
                          textDecoration: achieved ? 'line-through' : 'none',
                        },
                      }}
                    />
                  </ListItem>
                );
              })}
            </List>

            {/* Stats Row */}
            <Box
              sx={{
                display: 'flex',
                gap: 2,
                mt: 2,
                pt: 2,
                borderTop: '1px solid rgba(255,255,255,0.1)',
              }}
            >
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h6" sx={{ color: '#f44336' }}>
                  {progress.tools_executed}
                </Typography>
                <Typography variant="caption" sx={{ color: '#666' }}>
                  Tools
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h6" sx={{ color: '#ff9800' }}>
                  {progress.credentials_captured}
                </Typography>
                <Typography variant="caption" sx={{ color: '#666' }}>
                  Creds
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h6" sx={{ color: '#9c27b0' }}>
                  {progress.sessions_hijacked}
                </Typography>
                <Typography variant="caption" sx={{ color: '#666' }}>
                  Sessions
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h6" sx={{ color: '#2196f3' }}>
                  {progress.injections_successful}
                </Typography>
                <Typography variant="caption" sx={{ color: '#666' }}>
                  Injections
                </Typography>
              </Box>
              <Box sx={{ textAlign: 'center' }}>
                <Typography variant="h6" sx={{ color: '#4caf50' }}>
                  {progress.findings_generated}
                </Typography>
                <Typography variant="caption" sx={{ color: '#666' }}>
                  Findings
                </Typography>
              </Box>
            </Box>
          </Box>
        )}
      </Collapse>
    </Paper>
  );
};

export default MitmAttackPhaseIndicator;
