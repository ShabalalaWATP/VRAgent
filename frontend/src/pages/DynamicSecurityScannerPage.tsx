import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Chip,
  LinearProgress,
  Alert,
  Tabs,
  Tab,
  IconButton,
  Tooltip,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControlLabel,
  Checkbox,
  Switch,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  CircularProgress,
  Badge,
  alpha,
  keyframes,
} from '@mui/material';
import {
  PlayArrow,
  Stop,
  Refresh,
  ExpandMore,
  Security,
  Speed,
  BugReport,
  Computer,
  Web,
  Storage,
  ContentCopy,
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  Info,
  NetworkCheck,
  Radar,
  Terminal,
  Article,
  Code,
  Download,
  Visibility,
  Shield,
  Bolt,
  Memory,
  Router,
  Dangerous,
  GppBad,
  GppGood,
  Fingerprint,
  DataObject,
  Dns,
  SettingsEthernet,
  Hub,
  Psychology,
  Delete,
} from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import { 
  dynamicScannerClient,
  DynamicScanResult,
  DynamicScanProgress,
  DynamicScanFinding,
  DynamicScanHost,
  DynamicScanExploitChain,
} from '../api/client';
import DynamicScanAIChatWidget from '../components/DynamicScanAIChatWidget';

// ============================================================================
// CYBER THEME COLORS - Matrix Green Hacker Theme
// ============================================================================
const CYBER_COLORS = {
  primary: '#00ff41',        // Matrix Green
  primaryDark: '#00cc33',    // Darker Green
  primaryLight: '#39ff14',   // Neon Green
  secondary: '#00ffaa',      // Aqua Green
  accent: '#00fff7',         // Electric Cyan
  accentAlt: '#7fff00',      // Chartreuse
  danger: '#ff0055',         // Hot Pink Error
  warning: '#ffcc00',        // Golden Yellow
  success: '#00ff88',        // Mint Green
  info: '#00d4ff',           // Sky Blue
  dark: '#000a00',           // Deep Black-Green
  darkAlt: '#001a00',        // Slightly Lighter Green-Black
  surface: '#001f0f',        // Card Background
  surfaceLight: '#002f1a',   // Hover States
  text: '#b8ffb8',           // Light Green Text
  textMuted: '#66ff66',      // Muted Green
  glow: 'rgba(0, 255, 65, 0.6)',
  glowStrong: 'rgba(0, 255, 65, 0.95)',
  matrixRain: 'rgba(0, 255, 65, 0.15)',
};

// ============================================================================
// ANIMATIONS - Matrix / Hacker Style
// ============================================================================
const pulseGlow = keyframes`
  0%, 100% { 
    box-shadow: 0 0 5px ${CYBER_COLORS.glow}, 0 0 15px ${CYBER_COLORS.glow}, 0 0 25px ${CYBER_COLORS.glow};
    filter: brightness(1);
  }
  50% { 
    box-shadow: 0 0 15px ${CYBER_COLORS.glowStrong}, 0 0 30px ${CYBER_COLORS.glow}, 0 0 45px ${CYBER_COLORS.glow};
    filter: brightness(1.2);
  }
`;

const scanLine = keyframes`
  0% { transform: translateY(-100%); opacity: 0; }
  10% { opacity: 0.8; }
  90% { opacity: 0.8; }
  100% { transform: translateY(100vh); opacity: 0; }
`;

const dataFlow = keyframes`
  0% { background-position: 0% 50%; }
  50% { background-position: 100% 50%; }
  100% { background-position: 0% 50%; }
`;

const glitchFlicker = keyframes`
  0%, 100% { opacity: 1; text-shadow: 0 0 10px ${CYBER_COLORS.glow}; }
  92% { opacity: 1; }
  93% { opacity: 0.8; transform: translateX(-3px) skewX(-2deg); text-shadow: -2px 0 ${CYBER_COLORS.danger}, 2px 0 ${CYBER_COLORS.accent}; }
  94% { opacity: 1; transform: translateX(3px) skewX(2deg); text-shadow: 2px 0 ${CYBER_COLORS.danger}, -2px 0 ${CYBER_COLORS.accent}; }
  95% { opacity: 0.9; transform: translateX(-1px); }
  96% { opacity: 1; transform: translateX(0); text-shadow: 0 0 20px ${CYBER_COLORS.glowStrong}; }
`;

const radarSweep = keyframes`
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
`;

const matrixRain = keyframes`
  0% { background-position: 0% 0%; }
  100% { background-position: 0% 100%; }
`;

const hackingPulse = keyframes`
  0%, 100% { transform: scale(1); opacity: 0.8; }
  50% { transform: scale(1.05); opacity: 1; }
`;

const typeWriter = keyframes`
  from { width: 0; }
  to { width: 100%; }
`;

const blink = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0; }
`;

const floatUp = keyframes`
  0% { transform: translateY(20px); opacity: 0; }
  100% { transform: translateY(0); opacity: 1; }
`;

const borderGlow = keyframes`
  0%, 100% { border-color: ${CYBER_COLORS.primary}; }
  25% { border-color: ${CYBER_COLORS.accent}; }
  50% { border-color: ${CYBER_COLORS.secondary}; }
  75% { border-color: ${CYBER_COLORS.accentAlt}; }
`;

const spinGlow = keyframes`
  0% { transform: rotate(0deg); filter: hue-rotate(0deg); }
  100% { transform: rotate(360deg); filter: hue-rotate(360deg); }
`;

// ============================================================================
// STYLED COMPONENTS
// ============================================================================
interface CyberPaperProps {
  children: React.ReactNode;
  glowing?: boolean;
  sx?: object;
  [key: string]: any;
}

const CyberPaper: React.FC<CyberPaperProps> = ({ children, glowing = false, sx = {}, ...props }) => (
  <Paper
    {...props}
    sx={{
      background: `linear-gradient(145deg, ${CYBER_COLORS.surface} 0%, ${CYBER_COLORS.dark} 50%, ${CYBER_COLORS.darkAlt} 100%)`,
      border: `1px solid ${alpha(CYBER_COLORS.primary, 0.4)}`,
      borderRadius: 2,
      position: 'relative',
      overflow: 'hidden',
      transition: 'all 0.4s cubic-bezier(0.4, 0, 0.2, 1)',
      '&::before': {
        content: '""',
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: '2px',
        background: `linear-gradient(90deg, transparent, ${CYBER_COLORS.primary}, ${CYBER_COLORS.accent}, ${CYBER_COLORS.primary}, transparent)`,
        animation: `${dataFlow} 3s ease infinite`,
        backgroundSize: '200% 200%',
      },
      '&::after': {
        content: '""',
        position: 'absolute',
        inset: 0,
        background: `repeating-linear-gradient(
          0deg,
          transparent,
          transparent 2px,
          ${CYBER_COLORS.matrixRain} 2px,
          ${CYBER_COLORS.matrixRain} 4px
        )`,
        pointerEvents: 'none',
        opacity: 0.3,
      },
      '&:hover': {
        borderColor: CYBER_COLORS.primary,
        boxShadow: `0 0 30px ${CYBER_COLORS.glow}, inset 0 0 60px ${alpha(CYBER_COLORS.primary, 0.05)}`,
        transform: 'translateY(-2px)',
      },
      ...(glowing && {
        animation: `${pulseGlow} 2s ease-in-out infinite, ${borderGlow} 4s ease infinite`,
      }),
      ...sx,
    }}
  >
    {children}
  </Paper>
);

interface CyberCardProps {
  children: React.ReactNode;
  severity?: string;
  sx?: object;
  [key: string]: any;
}

const CyberCard: React.FC<CyberCardProps> = ({ children, severity, sx = {}, ...props }) => {
  const getCardColor = () => {
    switch (severity) {
      case 'critical': return CYBER_COLORS.danger;
      case 'high': return '#ff6600';
      case 'medium': return CYBER_COLORS.warning;
      case 'low': return CYBER_COLORS.success;
      default: return CYBER_COLORS.primary;
    }
  };
  
  return (
    <Card
      {...props}
      sx={{
        background: `linear-gradient(145deg, ${alpha(getCardColor(), 0.15)} 0%, ${CYBER_COLORS.dark} 60%, ${alpha(getCardColor(), 0.05)} 100%)`,
        border: `1px solid ${alpha(getCardColor(), 0.5)}`,
        borderRadius: 2,
        transition: 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
        position: 'relative',
        overflow: 'hidden',
        animation: `${floatUp} 0.5s ease-out`,
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: '-100%',
          width: '100%',
          height: '100%',
          background: `linear-gradient(90deg, transparent, ${alpha(getCardColor(), 0.1)}, transparent)`,
          transition: 'left 0.5s ease',
        },
        '&:hover': {
          borderColor: getCardColor(),
          boxShadow: `0 0 25px ${alpha(getCardColor(), 0.4)}, 0 8px 32px ${alpha(getCardColor(), 0.2)}`,
          transform: 'translateY(-4px) scale(1.01)',
          '&::before': {
            left: '100%',
          },
        },
        '&:active': {
          transform: 'translateY(-2px) scale(0.99)',
        },
        ...sx,
      }}
    >
      {children}
    </Card>
  );
};

interface GlitchTextProps {
  children: React.ReactNode;
  variant?: 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6';
  sx?: object;
  [key: string]: any;
}

const GlitchText: React.FC<GlitchTextProps> = ({ children, variant = 'h4', sx = {}, ...props }) => (
  <Typography
    variant={variant}
    {...props}
    sx={{
      fontFamily: '"Orbitron", "Rajdhani", "Share Tech Mono", monospace',
      fontWeight: 700,
      letterSpacing: '0.15em',
      textTransform: 'uppercase',
      background: `linear-gradient(90deg, ${CYBER_COLORS.primary} 0%, ${CYBER_COLORS.accent} 25%, ${CYBER_COLORS.secondary} 50%, ${CYBER_COLORS.accentAlt} 75%, ${CYBER_COLORS.primary} 100%)`,
      backgroundSize: '200% auto',
      backgroundClip: 'text',
      WebkitBackgroundClip: 'text',
      color: 'transparent',
      textShadow: `0 0 20px ${CYBER_COLORS.glow}, 0 0 40px ${alpha(CYBER_COLORS.primary, 0.3)}`,
      animation: `${glitchFlicker} 3s infinite, ${dataFlow} 4s linear infinite`,
      position: 'relative',
      '&::before': {
        content: 'attr(data-text)',
        position: 'absolute',
        left: 2,
        top: 0,
        color: CYBER_COLORS.danger,
        opacity: 0,
      },
      '&:hover': {
        textShadow: `0 0 30px ${CYBER_COLORS.glowStrong}, 0 0 60px ${CYBER_COLORS.glow}`,
      },
      ...sx,
    }}
  >
    {children}
  </Typography>
);

interface NeonChipProps {
  label: string;
  color?: string;
  size?: 'small' | 'medium';
  icon?: React.ReactElement;
  sx?: object;
  [key: string]: any;
}

const NeonChip: React.FC<NeonChipProps> = ({ label, color = 'primary', size = 'small', icon, sx: customSx = {}, ...props }) => {
  const chipColors: Record<string, string> = {
    primary: CYBER_COLORS.primary,
    success: CYBER_COLORS.success,
    warning: CYBER_COLORS.warning,
    danger: CYBER_COLORS.danger,
    info: CYBER_COLORS.info,
    critical: '#ff0044',
    high: '#ff6600',
    medium: '#ffaa00',
    low: '#00ff88',
  };
  const c = chipColors[color] || chipColors.primary;
  
  return (
    <Chip
      label={label}
      size={size}
      icon={icon}
      {...props}
      sx={{
        bgcolor: alpha(c, 0.15),
        color: c,
        border: `1px solid ${alpha(c, 0.6)}`,
        fontFamily: '"Share Tech Mono", monospace',
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        textShadow: `0 0 8px ${alpha(c, 0.5)}`,
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        cursor: 'pointer',
        '&:hover': {
          bgcolor: alpha(c, 0.25),
          boxShadow: `0 0 15px ${alpha(c, 0.6)}, 0 0 30px ${alpha(c, 0.3)}`,
          transform: 'scale(1.05)',
          borderColor: c,
        },
        '&:active': {
          transform: 'scale(0.98)',
        },
        ...customSx,
      }}
    />
  );
};

interface TerminalBoxProps {
  children: React.ReactNode;
  title?: string;
  sx?: object;
  [key: string]: any;
}

const TerminalBox: React.FC<TerminalBoxProps> = ({ children, title, sx = {}, ...props }) => (
  <Box
    {...props}
    sx={{
      bgcolor: alpha(CYBER_COLORS.dark, 0.9),
      border: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
      borderRadius: 1,
      overflow: 'hidden',
      ...sx,
    }}
  >
    {title && (
      <Box
        sx={{
          bgcolor: alpha(CYBER_COLORS.primary, 0.1),
          borderBottom: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
          px: 2,
          py: 0.5,
          display: 'flex',
          alignItems: 'center',
          gap: 1,
        }}
      >
        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: CYBER_COLORS.danger }} />
        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: CYBER_COLORS.warning }} />
        <Box sx={{ width: 8, height: 8, borderRadius: '50%', bgcolor: CYBER_COLORS.success }} />
        <Typography
          variant="caption"
          sx={{
            ml: 1,
            color: CYBER_COLORS.textMuted,
            fontFamily: '"Share Tech Mono", monospace',
            textTransform: 'uppercase',
            letterSpacing: '0.1em',
          }}
        >
          {title}
        </Typography>
      </Box>
    )}
    <Box sx={{ p: 2 }}>{children}</Box>
  </Box>
);

interface CyberButtonProps {
  children: React.ReactNode;
  variant?: 'contained' | 'outlined' | 'text';
  color?: string;
  glowing?: boolean;
  sx?: object;
  [key: string]: any;
}

const CyberButton: React.FC<CyberButtonProps> = ({ children, variant = 'contained', color = 'primary', glowing = false, sx = {}, ...props }) => {
  const isContained = variant === 'contained';
  
  return (
    <Button
      variant={variant}
      {...props}
      sx={{
        fontFamily: '"Orbitron", "Rajdhani", sans-serif',
        fontWeight: 700,
        letterSpacing: '0.15em',
        textTransform: 'uppercase',
        borderRadius: 1,
        px: 4,
        py: 1.5,
        position: 'relative',
        overflow: 'hidden',
        transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
        textShadow: `0 0 10px ${CYBER_COLORS.glow}`,
        ...(isContained ? {
          background: `linear-gradient(135deg, ${CYBER_COLORS.primary} 0%, ${CYBER_COLORS.primaryDark} 50%, ${CYBER_COLORS.primary} 100%)`,
          backgroundSize: '200% 200%',
          color: '#000',
          border: `2px solid ${CYBER_COLORS.primaryLight}`,
          boxShadow: `0 0 15px ${alpha(CYBER_COLORS.primary, 0.4)}, inset 0 0 20px ${alpha(CYBER_COLORS.primaryLight, 0.2)}`,
          '&:hover': {
            backgroundPosition: '100% 0%',
            boxShadow: `0 0 30px ${CYBER_COLORS.glow}, 0 0 60px ${alpha(CYBER_COLORS.primary, 0.4)}, inset 0 0 30px ${alpha(CYBER_COLORS.primaryLight, 0.3)}`,
            transform: 'translateY(-2px) scale(1.02)',
          },
          '&:active': {
            transform: 'translateY(0) scale(0.98)',
          },
        } : {
          color: CYBER_COLORS.primary,
          border: `2px solid ${CYBER_COLORS.primary}`,
          background: 'transparent',
          '&:hover': {
            bgcolor: alpha(CYBER_COLORS.primary, 0.15),
            boxShadow: `0 0 20px ${CYBER_COLORS.glow}, inset 0 0 20px ${alpha(CYBER_COLORS.primary, 0.1)}`,
            transform: 'translateY(-2px)',
          },
        }),
        ...(glowing && {
          animation: `${pulseGlow} 1.5s ease-in-out infinite, ${hackingPulse} 2s ease-in-out infinite`,
        }),
        '&::before': {
          content: '""',
          position: 'absolute',
          top: 0,
          left: '-100%',
          width: '100%',
          height: '100%',
          background: `linear-gradient(90deg, transparent, ${alpha(CYBER_COLORS.primaryLight, 0.5)}, transparent)`,
          transition: 'left 0.6s ease',
        },
        '&:hover::before': {
          left: '100%',
        },
        '&::after': {
          content: '""',
          position: 'absolute',
          inset: 0,
          borderRadius: 'inherit',
          background: `linear-gradient(45deg, transparent 40%, ${alpha(CYBER_COLORS.accent, 0.1)} 50%, transparent 60%)`,
          backgroundSize: '200% 200%',
          animation: `${dataFlow} 3s linear infinite`,
        },
        ...sx,
      }}
    >
      {children}
    </Button>
  );
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================
const normalizeSeverity = (severity?: string) => (severity || 'info').toLowerCase();
const formatSeverity = (severity?: string) => normalizeSeverity(severity).toUpperCase();

const getSeverityColor = (severity: string) => {
  switch (normalizeSeverity(severity)) {
    case 'critical': return '#ff0055';
    case 'high': return '#ff6600';
    case 'medium': return '#ffcc00';
    case 'low': return '#00ff88';
    case 'info': return CYBER_COLORS.info;
    default: return CYBER_COLORS.textMuted;
  }
};

const getSeverityIcon = (severity: string) => {
  const color = getSeverityColor(severity);
  switch (normalizeSeverity(severity)) {
    case 'critical': return <Dangerous sx={{ color }} />;
    case 'high': return <GppBad sx={{ color }} />;
    case 'medium': return <Warning sx={{ color }} />;
    case 'low': return <Info sx={{ color }} />;
    default: return <Info sx={{ color }} />;
  }
};

const phaseInfo: Record<string, { icon: React.ReactNode; label: string; color: string }> = {
  initializing: { icon: <Memory />, label: 'INITIALIZING SYSTEMS', color: CYBER_COLORS.textMuted },
  reconnaissance: { icon: <Radar />, label: 'NMAP RECONNAISSANCE', color: CYBER_COLORS.accent },
  routing: { icon: <Hub />, label: 'AI SERVICE ROUTING', color: CYBER_COLORS.secondary },
  directory_enumeration: { icon: <Dns />, label: 'DIRECTORY ENUMERATION', color: CYBER_COLORS.secondary },
  openvas_scanning: { icon: <Shield />, label: 'OPENVAS NETWORK SCAN', color: CYBER_COLORS.warning },
  web_scanning: { icon: <Web />, label: 'ZAP WEB SCANNING', color: CYBER_COLORS.info },
  wapiti_scanning: { icon: <Security />, label: 'WAPITI SCANNING', color: CYBER_COLORS.warning },
  sqlmap_scanning: { icon: <Terminal />, label: 'SQLMAP INJECTION', color: CYBER_COLORS.danger },
  cve_scanning: { icon: <BugReport />, label: 'NUCLEI CVE SCANNING', color: '#f97316' },
  exploit_mapping: { icon: <Fingerprint />, label: 'EXPLOIT MAPPING', color: CYBER_COLORS.danger },
  ai_analysis: { icon: <Psychology />, label: 'AI ANALYSIS', color: CYBER_COLORS.primary },
  completed: { icon: <GppGood />, label: 'SCAN COMPLETE', color: CYBER_COLORS.success },
  failed: { icon: <ErrorIcon />, label: 'SCAN FAILED', color: CYBER_COLORS.danger },
  cancelled: { icon: <Stop />, label: 'CANCELLED', color: CYBER_COLORS.textMuted },
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================
const DynamicSecurityScannerPage: React.FC = () => {
  const theme = useTheme();
  
  // Form state
  const [scanName, setScanName] = useState('');
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('service');
  const [ports, setPorts] = useState('');
  const [includeWebScan, setIncludeWebScan] = useState(true);
  const [includeCveScan, setIncludeCveScan] = useState(true);
  const [includeExploitMapping, setIncludeExploitMapping] = useState(true);
  const [includeOpenvas, setIncludeOpenvas] = useState(true);
  const [includeDirectoryEnum, setIncludeDirectoryEnum] = useState(true);
  const [includeSqlmap, setIncludeSqlmap] = useState(true);
  const [includeWapiti, setIncludeWapiti] = useState(true);
  
  // AI-Led mode
  const [aiLedMode, setAiLedMode] = useState(true);  // Default to AI-led
  const [userContext, setUserContext] = useState('');
  const [aggressiveScan, setAggressiveScan] = useState(true);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [authMethod, setAuthMethod] = useState('form');
  const [authLoginUrl, setAuthLoginUrl] = useState('');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authRequestData, setAuthRequestData] = useState('');
  const [authLoggedInIndicator, setAuthLoggedInIndicator] = useState('');
  const [authLoggedOutIndicator, setAuthLoggedOutIndicator] = useState('');
  const [authContextName, setAuthContextName] = useState('');
  const [forcedBrowseEnabled, setForcedBrowseEnabled] = useState(false);
  const [forcedBrowseWordlist, setForcedBrowseWordlist] = useState('');
  
  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<DynamicScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Saved scans state
  const [savedScans, setSavedScans] = useState<any[]>([]);
  const [loadingSavedScans, setLoadingSavedScans] = useState(false);
  const [manualGuidance, setManualGuidance] = useState<string[]>([]);
  const [manualScanProfile, setManualScanProfile] = useState<Record<string, any> | null>(null);
  const [manualGuidanceLoading, setManualGuidanceLoading] = useState(false);
  
  // UI state
  const [activeTab, setActiveTab] = useState(0);
  const [expandedFinding, setExpandedFinding] = useState<number | null>(null);
  const [findingExplanation, setFindingExplanation] = useState<string | null>(null);
  const [loadingExplanation, setLoadingExplanation] = useState(false);
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);
  
  // Scanner status
  const [scannerStatus, setScannerStatus] = useState<'connected' | 'disconnected' | 'checking'>('checking');
  
  // Load saved scans on mount
  useEffect(() => {
    const loadSavedScans = async () => {
      setLoadingSavedScans(true);
      try {
        const response = await dynamicScannerClient.listScans();
        setSavedScans(response.historical_scans || []);
      } catch (err) {
        console.error('Error loading saved scans:', err);
      } finally {
        setLoadingSavedScans(false);
      }
    };
    loadSavedScans();
  }, []);
  
  // Refresh saved scans when a scan completes
  useEffect(() => {
    if (scanResult && ['completed', 'failed'].includes(scanResult.status)) {
      const loadSavedScans = async () => {
        try {
          const response = await dynamicScannerClient.listScans();
          setSavedScans(response.historical_scans || []);
        } catch (err) {
          console.error('Error refreshing saved scans:', err);
        }
      };
      loadSavedScans();
    }
  }, [scanResult?.status]);
  
  // Check scanner status
  useEffect(() => {
    const checkScanner = async () => {
      try {
        const response = await dynamicScannerClient.getScannerStatus();
        setScannerStatus(response.status === 'connected' ? 'connected' : 'disconnected');
      } catch {
        setScannerStatus('disconnected');
      }
    };
    checkScanner();
    const interval = setInterval(checkScanner, 30000);
    return () => clearInterval(interval);
  }, []);
  
  // Poll for scan results
  useEffect(() => {
    if (!scanId || !isScanning) return;
    
    const pollResults = async () => {
      try {
        const result = await dynamicScannerClient.getScanResults(scanId);
        setScanResult(result);
        
        if (['completed', 'failed', 'cancelled'].includes(result.status)) {
          setIsScanning(false);
        }
      } catch (err) {
        console.error('Error polling results:', err);
      }
    };
    
    const interval = setInterval(pollResults, 3000);
    return () => clearInterval(interval);
  }, [scanId, isScanning]);

  useEffect(() => {
    if (aiLedMode) {
      setManualGuidance([]);
      setManualScanProfile(null);
      setManualGuidanceLoading(false);
      return;
    }

    let cancelled = false;

    const fetchGuidance = async () => {
      setManualGuidanceLoading(true);
      try {
      const response = await dynamicScannerClient.getManualGuidance({
          aggressive_scan: aggressiveScan,
          include_openvas: includeOpenvas,
          include_web_scan: includeWebScan,
          include_cve_scan: includeCveScan,
          include_directory_enum: includeDirectoryEnum,
          include_sqlmap: includeSqlmap,
          include_wapiti: includeWapiti,
        });
        if (cancelled) return;
        setManualGuidance(response.manual_guidance);
        setManualScanProfile(response.scan_profile);
      } catch (err) {
        console.error('Manual guidance fetch failed:', err);
      } finally {
        if (!cancelled) {
          setManualGuidanceLoading(false);
        }
      }
    };

    fetchGuidance();

    return () => {
      cancelled = true;
    };
  }, [aiLedMode, aggressiveScan, includeOpenvas, includeWebScan, includeCveScan, includeDirectoryEnum, includeSqlmap, includeWapiti]);
  
  // Load a saved scan
  const handleLoadSavedScan = async (savedScanId: string) => {
    try {
      const result = await dynamicScannerClient.getScanResults(savedScanId);
      setScanResult(result);
      setScanId(savedScanId);
      setActiveTab(0);
    } catch (err) {
      console.error('Error loading saved scan:', err);
      setError('Failed to load saved scan');
    }
  };
  
  // Delete a saved scan
  const handleDeleteScan = async (scanIdToDelete: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan? This cannot be undone.')) {
      return;
    }
    try {
      await dynamicScannerClient.deleteScan(scanIdToDelete);
      // Refresh saved scans list
      const response = await dynamicScannerClient.listScans();
      setSavedScans(response.historical_scans || []);
      // Clear current scan if it was the deleted one
      if (scanId === scanIdToDelete) {
        setScanId(null);
        setScanResult(null);
      }
    } catch (err) {
      console.error('Error deleting scan:', err);
      setError('Failed to delete scan');
    }
  };
  
  // Start scan
  const handleStartScan = async () => {
    if (!target.trim()) {
      setError('Please enter a target');
      return;
    }

    if (authEnabled) {
      const needsLoginUrl = authMethod === 'form' || authMethod === 'json';
      if (needsLoginUrl && !authLoginUrl.trim()) {
        setError('Authenticated scan requires a login URL');
        return;
      }
      if (!authUsername.trim() || !authPassword) {
        setError('Authenticated scan requires username and password');
        return;
      }
    }
    
    setError(null);
    setIsScanning(true);
    setScanResult(null);
    
    try {
      const zapAuth = authEnabled ? {
        method: authMethod,
        login_url: authLoginUrl.trim() || undefined,
        login_request_data: authRequestData.trim() || undefined,
        username: authUsername.trim() || undefined,
        password: authPassword || undefined,
        logged_in_indicator: authLoggedInIndicator.trim() || undefined,
        logged_out_indicator: authLoggedOutIndicator.trim() || undefined,
        context_name: authContextName.trim() || undefined,
      } : undefined;

      const response = await dynamicScannerClient.startScan({
        scan_name: scanName.trim() || undefined,
        target: target.trim(),
        scan_type: scanType,
        ports: ports.trim() || undefined,
        include_web_scan: includeWebScan,
        include_cve_scan: includeCveScan,
        include_exploit_mapping: includeExploitMapping,
        include_openvas: includeOpenvas,
        include_directory_enum: includeDirectoryEnum,
        include_sqlmap: includeSqlmap,
        include_wapiti: includeWapiti,
        ai_led: aiLedMode,
        user_context: userContext.trim() || undefined,
        aggressive_scan: aggressiveScan,
        zap_auth: zapAuth,
        zap_forced_browse: forcedBrowseEnabled,
        zap_wordlist: forcedBrowseWordlist.trim() || undefined,
      });
      
      setScanId(response.scan_id);
      
      const result = await dynamicScannerClient.getScanResults(response.scan_id);
      setScanResult(result);
      
    } catch (err: any) {
      setError(err.message || 'Failed to start scan');
      setIsScanning(false);
    }
  };
  
  // Cancel scan
  const handleCancelScan = async () => {
    if (!scanId) return;
    try {
      await dynamicScannerClient.cancelScan(scanId);
      setIsScanning(false);
    } catch (err) {
      console.error('Error cancelling scan:', err);
    }
  };
  
  // Copy command
  const handleCopyCommand = (command: string) => {
    navigator.clipboard.writeText(command);
    setCopiedCommand(command);
    setTimeout(() => setCopiedCommand(null), 2000);
  };
  
  // Get finding explanation
  const handleExplainFinding = async (findingIndex: number) => {
    if (!scanId) return;
    
    setLoadingExplanation(true);
    setFindingExplanation(null);
    
    try {
      const response = await dynamicScannerClient.explainFinding(scanId, findingIndex);
      setFindingExplanation(response.explanation);
    } catch (err) {
      setFindingExplanation('Failed to generate explanation');
    } finally {
      setLoadingExplanation(false);
    }
  };
  
  // Export results
  const handleExport = async (format: 'json' | 'markdown' | 'pdf' | 'docx') => {
    if (!scanId) return;
    
    try {
      const response = await dynamicScannerClient.exportResults(scanId, format);
      
      let blob: Blob;
      let filename: string;
      
      if (format === 'json') {
        blob = new Blob([JSON.stringify(response, null, 2)], { type: 'application/json' });
        filename = `pentest-${scanId}.json`;
      } else if (format === 'markdown') {
        blob = new Blob([response as string], { type: 'text/markdown' });
        filename = `pentest-${scanId}.md`;
      } else if (format === 'pdf') {
        blob = response as Blob;
        filename = `pentest-${scanId}.pdf`;
      } else if (format === 'docx') {
        blob = response as Blob;
        filename = `pentest-${scanId}.docx`;
      } else {
        return;
      }
      
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    }
  };
  
  // ============================================================================
  // RENDER FUNCTIONS
  // ============================================================================
  
  // Render cyber header
  const renderHeader = () => (
    <Box sx={{ mb: 4, position: 'relative' }}>
      {/* Animated background */}
      <Box
        sx={{
          position: 'absolute',
          top: -20,
          left: -20,
          right: -20,
          bottom: -20,
          background: `radial-gradient(ellipse at center, ${alpha(CYBER_COLORS.primary, 0.15)} 0%, transparent 70%)`,
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      
      <Box sx={{ position: 'relative', zIndex: 1, display: 'flex', alignItems: 'center', gap: 3 }}>
        {/* Animated Radar Icon */}
        <Box
          sx={{
            position: 'relative',
            width: 80,
            height: 80,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Box
            sx={{
              position: 'absolute',
              width: '100%',
              height: '100%',
              borderRadius: '50%',
              border: `2px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
            }}
          />
          <Box
            sx={{
              position: 'absolute',
              width: '70%',
              height: '70%',
              borderRadius: '50%',
              border: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
            }}
          />
          <Box
            sx={{
              position: 'absolute',
              width: '100%',
              height: '100%',
              borderRadius: '50%',
              background: `conic-gradient(from 0deg, transparent 0deg, ${alpha(CYBER_COLORS.primary, 0.4)} 30deg, transparent 60deg)`,
              animation: isScanning ? `${radarSweep} 2s linear infinite` : 'none',
            }}
          />
          <Shield sx={{ fontSize: 40, color: CYBER_COLORS.primary }} />
        </Box>
        
        <Box sx={{ flex: 1 }}>
          <GlitchText variant="h4">
            Dynamic Security Scanner
          </GlitchText>
          <Typography
            variant="body2"
            sx={{
              color: CYBER_COLORS.textMuted,
              fontFamily: '"Share Tech Mono", monospace',
              letterSpacing: '0.05em',
              mt: 0.5,
            }}
          >
            {'>'} AI-ORCHESTRATED AUTOMATED PENTESTING FRAMEWORK
          </Typography>
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <NeonChip label="NMAP" color="info" />
            <NeonChip label="OPENVAS" color="warning" />
            <NeonChip label="ZAP" color="primary" />
            <NeonChip label="NUCLEI" color="danger" />
            <NeonChip label="AI" color="success" />
          </Box>
        </Box>
        
        {/* Scanner Status */}
        <Box sx={{ textAlign: 'right' }}>
          <NeonChip
            icon={<SettingsEthernet />}
            label={scannerStatus === 'connected' ? 'SCANNER ONLINE' : 'SCANNER OFFLINE'}
            color={scannerStatus === 'connected' ? 'success' : 'warning'}
          />
        </Box>
      </Box>
    </Box>
  );

  const renderAdvancedOptions = () => {
    const authRequestPlaceholder = authMethod === 'json'
      ? '{"email":"{%username%}","password":"{%password%}"}'
      : 'username={%username%}&password={%password%}';

    return (
      <Accordion
        sx={{
          bgcolor: alpha(CYBER_COLORS.dark, 0.4),
          border: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
          '&::before': { display: 'none' },
        }}
      >
        <AccordionSummary expandIcon={<ExpandMore sx={{ color: CYBER_COLORS.primary }} />}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SettingsEthernet sx={{ color: CYBER_COLORS.primary }} />
            <Typography
              sx={{
                fontFamily: '"Share Tech Mono", monospace',
                color: CYBER_COLORS.text,
                letterSpacing: '0.08em',
              }}
            >
              ADVANCED OPTIONS
            </Typography>
          </Box>
        </AccordionSummary>
        <AccordionDetails>
        <Grid container spacing={2}>
          <Grid item xs={12}>
            <Typography
              sx={{
                fontFamily: '"Share Tech Mono", monospace',
                color: CYBER_COLORS.textMuted,
                fontSize: '0.75rem',
              }}
            >
              Aggressive mode is controlled via the toggle above. Keep it enabled for maximum depth, playful if you want a lighter + thorough scan.
            </Typography>
          </Grid>

            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={authEnabled}
                    onChange={(e) => setAuthEnabled(e.target.checked)}
                    disabled={isScanning}
                    sx={{ color: CYBER_COLORS.primary, '&.Mui-checked': { color: CYBER_COLORS.primary } }}
                  />
                }
                label={
                  <Typography sx={{ fontFamily: '"Share Tech Mono", monospace', color: CYBER_COLORS.textMuted }}>
                    AUTHENTICATED SCAN (ZAP)
                  </Typography>
                }
              />
            </Grid>

            {authEnabled && (
              <>
                <Grid item xs={12} md={3}>
                  <FormControl fullWidth>
                    <InputLabel sx={{ color: CYBER_COLORS.textMuted }}>AUTH METHOD</InputLabel>
                    <Select
                      value={authMethod}
                      label="AUTH METHOD"
                      onChange={(e) => setAuthMethod(e.target.value)}
                      disabled={isScanning}
                      sx={{
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                        color: CYBER_COLORS.text,
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                        '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                      }}
                    >
                      <MenuItem value="form">Form</MenuItem>
                      <MenuItem value="json">JSON / API</MenuItem>
                      <MenuItem value="basic">HTTP Basic</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="LOGIN URL"
                    placeholder="https://target.tld/login or /rest/user/login"
                    value={authLoginUrl}
                    onChange={(e) => setAuthLoginUrl(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                        '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={3}>
                  <TextField
                    fullWidth
                    label="CONTEXT NAME"
                    placeholder="Optional"
                    value={authContextName}
                    onChange={(e) => setAuthContextName(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                        '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    label="USERNAME"
                    value={authUsername}
                    onChange={(e) => setAuthUsername(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                        '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={4}>
                  <TextField
                    fullWidth
                    type="password"
                    label="PASSWORD"
                    value={authPassword}
                    onChange={(e) => setAuthPassword(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                        '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12}>
                  <TextField
                    fullWidth
                    multiline
                    minRows={2}
                    label="LOGIN REQUEST DATA"
                    placeholder={authRequestPlaceholder}
                    value={authRequestData}
                    onChange={(e) => setAuthRequestData(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.3),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.2) },
                        '&:hover fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.4) },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="LOGGED-IN INDICATOR (Regex)"
                    placeholder="e.g., Welcome|Logout"
                    value={authLoggedInIndicator}
                    onChange={(e) => setAuthLoggedInIndicator(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.3),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.2) },
                        '&:hover fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.4) },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
                <Grid item xs={12} md={6}>
                  <TextField
                    fullWidth
                    label="LOGGED-OUT INDICATOR (Regex)"
                    placeholder="e.g., Login|Sign In"
                    value={authLoggedOutIndicator}
                    onChange={(e) => setAuthLoggedOutIndicator(e.target.value)}
                    disabled={isScanning}
                    sx={{
                      '& .MuiOutlinedInput-root': {
                        fontFamily: '"Share Tech Mono", monospace',
                        bgcolor: alpha(CYBER_COLORS.dark, 0.3),
                        '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.2) },
                        '&:hover fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.4) },
                      },
                      '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                      '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    }}
                  />
                </Grid>
              </>
            )}

            <Grid item xs={12}>
              <Divider sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.2) }} />
            </Grid>

            <Grid item xs={12}>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={forcedBrowseEnabled}
                    onChange={(e) => setForcedBrowseEnabled(e.target.checked)}
                    disabled={isScanning}
                    sx={{ color: CYBER_COLORS.primary, '&.Mui-checked': { color: CYBER_COLORS.primary } }}
                  />
                }
                label={
                  <Typography sx={{ fontFamily: '"Share Tech Mono", monospace', color: CYBER_COLORS.textMuted }}>
                    FORCED BROWSE (WORDLIST ENUMERATION)
                  </Typography>
                }
              />
            </Grid>

            {forcedBrowseEnabled && (
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="WORDLIST"
                  placeholder="standard | api | directories_comprehensive.txt"
                  value={forcedBrowseWordlist}
                  onChange={(e) => setForcedBrowseWordlist(e.target.value)}
                  disabled={isScanning}
                  helperText="Use a wordlist key (standard/api/backup) or a filename in backend/wordlists"
                  sx={{
                    '& .MuiOutlinedInput-root': {
                      fontFamily: '"Share Tech Mono", monospace',
                      bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                      '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                      '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                    },
                    '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                    '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                    '& .MuiFormHelperText-root': { color: alpha(CYBER_COLORS.textMuted, 0.6), ml: 0 },
                  }}
                />
              </Grid>
            )}
          </Grid>
        </AccordionDetails>
      </Accordion>
    );
  };

  const renderManualGuidancePanel = () => {
    if (aiLedMode) return null;
    const guidance = scanResult?.manual_guidance?.length
      ? scanResult.manual_guidance
      : manualGuidance;
    if ((!guidance || guidance.length === 0) && !manualGuidanceLoading) {
      return null;
    }

    return (
      <CyberPaper sx={{ p: 2, mt: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
          <Bolt sx={{ color: CYBER_COLORS.primary }} />
          <Typography
            variant="h6"
            sx={{
              fontFamily: '"Rajdhani", sans-serif',
              fontWeight: 700,
              letterSpacing: '0.1em',
              color: CYBER_COLORS.primary,
            }}
          >
            Manual Scan Guidance
          </Typography>
          {manualGuidanceLoading && (
            <CircularProgress size={18} sx={{ color: CYBER_COLORS.primary }} />
          )}
        </Box>
        {manualScanProfile && (
          <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap', mb: 1 }}>
            <Chip
              label={`Depth: ${manualScanProfile.scan_depth}`}
              size="small"
              sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.4), color: CYBER_COLORS.primary }}
            />
            <Chip
              label={`ZAP: ${manualScanProfile.zap_policy}`}
              size="small"
              sx={{ borderColor: alpha(CYBER_COLORS.info, 0.4), color: CYBER_COLORS.info }}
            />
            <Chip
              label={`OpenVAS: ${manualScanProfile.openvas_config}`}
              size="small"
              sx={{ borderColor: alpha(CYBER_COLORS.warning, 0.4), color: CYBER_COLORS.warning }}
            />
            <Chip
              label={`Nuclei: ${manualScanProfile.nuclei_templates?.join(', ') || 'n/a'}`}
              size="small"
              sx={{ borderColor: alpha(CYBER_COLORS.danger, 0.4), color: CYBER_COLORS.danger }}
            />
          </Box>
        )}
        <List disablePadding>
          {guidance && guidance.map((step, idx) => (
            <ListItem key={idx} sx={{ py: 0.5 }}>
              <ListItemIcon sx={{ minWidth: 32 }}>
                <CheckCircle sx={{ color: CYBER_COLORS.primary, fontSize: 20 }} />
              </ListItemIcon>
              <ListItemText
                primary={step}
                primaryTypographyProps={{ fontFamily: '"Share Tech Mono", monospace', fontSize: '0.85rem' }}
              />
            </ListItem>
          ))}
        </List>
      </CyberPaper>
    );
  };
  
  // Render configuration panel
  const renderConfig = () => (
    <CyberPaper sx={{ p: 3, mb: 3 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Bolt sx={{ color: CYBER_COLORS.primary }} />
          <Typography
            variant="h6"
            sx={{
              fontFamily: '"Rajdhani", sans-serif',
              fontWeight: 700,
              color: CYBER_COLORS.text,
              letterSpacing: '0.1em',
            }}
          >
            {aiLedMode ? 'AI-POWERED ATTACK' : 'ATTACK CONFIGURATION'}
          </Typography>
        </Box>

        {/* AI Mode Toggle */}
        <Box
          onClick={() => !isScanning && setAiLedMode(!aiLedMode)}
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 1,
            px: 2,
            py: 1,
            borderRadius: 2,
            cursor: isScanning ? 'default' : 'pointer',
            opacity: isScanning ? 0.5 : 1,
            border: `1px solid ${aiLedMode ? CYBER_COLORS.primary : alpha(CYBER_COLORS.textMuted, 0.3)}`,
            bgcolor: aiLedMode ? alpha(CYBER_COLORS.primary, 0.15) : 'transparent',
            transition: 'all 0.3s ease',
            '&:hover': !isScanning ? {
              bgcolor: alpha(CYBER_COLORS.primary, aiLedMode ? 0.25 : 0.1),
              boxShadow: `0 0 15px ${alpha(CYBER_COLORS.primary, 0.3)}`,
            } : {},
          }}
        >
          <Psychology sx={{ 
            color: aiLedMode ? CYBER_COLORS.primary : CYBER_COLORS.textMuted,
            fontSize: 20,
            animation: aiLedMode ? `${pulseGlow} 2s ease-in-out infinite` : 'none',
          }} />
          <Typography
            sx={{
              fontFamily: '"Share Tech Mono", monospace',
              fontSize: '0.75rem',
              color: aiLedMode ? CYBER_COLORS.primary : CYBER_COLORS.textMuted,
              letterSpacing: '0.1em',
            }}
          >
            AI MODE {aiLedMode ? 'ON' : 'OFF'}
          </Typography>
        </Box>
      </Box>

      <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 2, flexWrap: 'wrap' }}>
        <FormControlLabel
          control={
            <Switch
              checked={aggressiveScan}
              onChange={(e) => setAggressiveScan(e.target.checked)}
              disabled={isScanning}
              color="primary"
            />
          }
          label={
            <Typography sx={{ fontFamily: '"Share Tech Mono", monospace', color: CYBER_COLORS.text }}>
              Aggressive depth (default). Uncheck for a thorough session with lower intensity.
            </Typography>
          }
          sx={{ ml: 0 }}
        />
      </Box>
      
      {aiLedMode ? (
        /* AI-LED MODE - Simplified UI */
        <Grid container spacing={3}>
          <Grid item xs={12} md={4}>
            <TextField
              fullWidth
              label="SCAN NAME (optional)"
              placeholder="e.g., Production Server Audit"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              disabled={isScanning}
              helperText="Name to identify this scan in history"
              InputProps={{
                startAdornment: <Article sx={{ color: CYBER_COLORS.secondary, mr: 1 }} />,
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  fontFamily: '"Share Tech Mono", monospace',
                  bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                  '& fieldset': { borderColor: alpha(CYBER_COLORS.secondary, 0.3) },
                  '&:hover fieldset': { borderColor: CYBER_COLORS.secondary },
                  '&.Mui-focused fieldset': { borderColor: CYBER_COLORS.secondary },
                },
                '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                '& .MuiFormHelperText-root': { color: alpha(CYBER_COLORS.textMuted, 0.6), ml: 0 },
              }}
            />
          </Grid>
          
          <Grid item xs={12} md={5}>
            <TextField
              fullWidth
              label="TARGET"
              placeholder="Enter IP, CIDR, URL, or hostname - AI will handle the rest"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isScanning}
              helperText={
                <Typography
                  component="span"
                  sx={{
                    color: alpha(CYBER_COLORS.textMuted, 0.7),
                    fontFamily: '"Share Tech Mono", monospace',
                    fontSize: '0.7rem',
                  }}
                >
                  🤖 AI will analyze target and choose optimal scan strategy
                </Typography>
              }
              InputProps={{
                startAdornment: <Router sx={{ color: CYBER_COLORS.primary, mr: 1 }} />,
              }}
              sx={{
                '& .MuiOutlinedInput-root': {
                  fontFamily: '"Share Tech Mono", monospace',
                  bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                  fontSize: '1.1rem',
                  '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.4) },
                  '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                  '&.Mui-focused fieldset': { 
                    borderColor: CYBER_COLORS.primary, 
                    boxShadow: `0 0 15px ${alpha(CYBER_COLORS.primary, 0.4)}` 
                  },
                },
                '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                '& .MuiInputBase-input': { color: CYBER_COLORS.text },
                '& .MuiFormHelperText-root': { ml: 0 },
              }}
            />
          </Grid>
          
          <Grid item xs={12} md={3}>
            {isScanning ? (
              <CyberButton
                fullWidth
                color="danger"
                onClick={handleCancelScan}
                startIcon={<Stop />}
                sx={{ height: 56, bgcolor: CYBER_COLORS.danger }}
              >
                ABORT
              </CyberButton>
            ) : (
              <CyberButton
                fullWidth
                onClick={handleStartScan}
                startIcon={<Psychology />}
                glowing
                sx={{ height: 56 }}
              >
                LET AI ATTACK
              </CyberButton>
            )}
          </Grid>
          
          <Grid item xs={12}>
            <TextField
              fullWidth
              multiline
              rows={2}
              label="CONTEXT FOR AI (Optional)"
              placeholder="e.g., 'This is a production e-commerce site', 'Focus on SQL injection', 'Looking for auth bypass vulnerabilities'..."
              value={userContext}
              onChange={(e) => setUserContext(e.target.value)}
              disabled={isScanning}
              sx={{
                '& .MuiOutlinedInput-root': {
                  fontFamily: '"Share Tech Mono", monospace',
                  bgcolor: alpha(CYBER_COLORS.dark, 0.3),
                  '& fieldset': { 
                    borderColor: alpha(CYBER_COLORS.primary, 0.2),
                    borderStyle: 'dashed',
                  },
                  '&:hover fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.4) },
                  '&.Mui-focused fieldset': { borderColor: CYBER_COLORS.primary },
                },
                '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
                '& .MuiInputBase-input': { color: CYBER_COLORS.text },
              }}
            />
          </Grid>

          <Grid item xs={12}>
            {renderAdvancedOptions()}
          </Grid>
          
          <Grid item xs={12}>
            <Box
              sx={{
                p: 2,
                borderRadius: 1,
                bgcolor: alpha(CYBER_COLORS.primary, 0.05),
                border: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
              }}
            >
              <Typography
                sx={{
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.8rem',
                  color: CYBER_COLORS.textMuted,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 1,
                }}
              >
                <Psychology sx={{ fontSize: 16, color: CYBER_COLORS.primary }} />
                AI will automatically: detect target type → decide if Nmap needed → select scan type →
                run appropriate vulnerability scanners → map exploits → generate attack narrative
              </Typography>
            </Box>
          </Grid>
        </Grid>
      ) : (
        /* MANUAL MODE - Full Configuration */
        <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            label="TARGET"
            placeholder="IP / CIDR / URL / Hostname"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={isScanning}
            helperText={
              <Typography
                component="span"
                sx={{
                  color: alpha(CYBER_COLORS.textMuted, 0.7),
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.7rem',
                }}
              >
                e.g., 192.168.1.0/24, https://app.example.com, scanme.nmap.org
              </Typography>
            }
            InputProps={{
              startAdornment: <Router sx={{ color: CYBER_COLORS.primary, mr: 1 }} />,
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                fontFamily: '"Share Tech Mono", monospace',
                bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
                '&.Mui-focused fieldset': { borderColor: CYBER_COLORS.primary, boxShadow: `0 0 10px ${alpha(CYBER_COLORS.primary, 0.3)}` },
              },
              '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
              '& .MuiInputBase-input': { color: CYBER_COLORS.text },
              '& .MuiFormHelperText-root': { ml: 0 },
            }}
          />
        </Grid>
        
        <Grid item xs={12} md={3}>
          <FormControl fullWidth>
            <InputLabel sx={{ color: CYBER_COLORS.textMuted }}>SCAN MODE</InputLabel>
            <Select
              value={scanType}
              label="SCAN MODE"
              onChange={(e) => setScanType(e.target.value)}
              disabled={isScanning}
              sx={{
                fontFamily: '"Share Tech Mono", monospace',
                bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                color: CYBER_COLORS.text,
                '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
              }}
            >
              <MenuItem value="ping">⚡ PING SWEEP</MenuItem>
              <MenuItem value="basic">🔍 BASIC SCAN</MenuItem>
              <MenuItem value="service">🎯 SERVICE DETECTION</MenuItem>
              <MenuItem value="comprehensive">💀 COMPREHENSIVE</MenuItem>
              <MenuItem value="stealth">🥷 STEALTH MODE</MenuItem>
              <MenuItem value="udp">📡 UDP SCAN</MenuItem>
            </Select>
          </FormControl>
        </Grid>
        
        <Grid item xs={12} md={3}>
          <TextField
            fullWidth
            label="PORTS"
            placeholder="22,80,443 or 1-1000"
            value={ports}
            onChange={(e) => setPorts(e.target.value)}
            disabled={isScanning}
            sx={{
              '& .MuiOutlinedInput-root': {
                fontFamily: '"Share Tech Mono", monospace',
                bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                '& fieldset': { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                '&:hover fieldset': { borderColor: CYBER_COLORS.primary },
              },
              '& .MuiInputLabel-root': { color: CYBER_COLORS.textMuted },
              '& .MuiInputBase-input': { color: CYBER_COLORS.text },
            }}
          />
        </Grid>
        
        <Grid item xs={12} md={2}>
          {isScanning ? (
            <CyberButton
              fullWidth
              color="danger"
              onClick={handleCancelScan}
              startIcon={<Stop />}
              sx={{ height: 56, bgcolor: CYBER_COLORS.danger }}
            >
              ABORT
            </CyberButton>
          ) : (
            <CyberButton
              fullWidth
              onClick={handleStartScan}
              startIcon={<Bolt />}
              glowing
              sx={{ height: 56 }}
            >
              ENGAGE
            </CyberButton>
          )}
        </Grid>
        
        <Grid item xs={12}>
          <Box
            sx={{
              display: 'flex',
              gap: 3,
              flexWrap: 'wrap',
              p: 2,
              bgcolor: alpha(CYBER_COLORS.dark, 0.3),
              borderRadius: 1,
              border: `1px dashed ${alpha(CYBER_COLORS.primary, 0.2)}`,
            }}
          >
            {[
              { checked: includeWebScan, set: setIncludeWebScan, label: 'ZAP WEB SCAN', icon: <Web /> },
              { checked: includeCveScan, set: setIncludeCveScan, label: 'NUCLEI CVE', icon: <BugReport /> },
              { checked: includeExploitMapping, set: setIncludeExploitMapping, label: 'EXPLOIT MAP', icon: <Fingerprint /> },
              { checked: includeOpenvas, set: setIncludeOpenvas, label: 'OPENVAS', icon: <Shield /> },
              { checked: includeDirectoryEnum, set: setIncludeDirectoryEnum, label: 'DIRECTORY ENUM (Gobuster/Dirbuster)', icon: <Dns /> },
              { checked: includeSqlmap, set: setIncludeSqlmap, label: 'SQLMAP INJECTION', icon: <Terminal /> },
              { checked: includeWapiti, set: setIncludeWapiti, label: 'WAPITI SCAN', icon: <Security /> },
            ].map((opt, i) => (
              <FormControlLabel
                key={i}
                control={
                  <Checkbox
                    checked={opt.checked}
                    onChange={(e) => opt.set(e.target.checked)}
                    disabled={isScanning}
                    sx={{
                      color: CYBER_COLORS.primary,
                      '&.Mui-checked': { color: CYBER_COLORS.primary },
                    }}
                  />
                }
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    {React.cloneElement(opt.icon, { sx: { fontSize: 18, color: CYBER_COLORS.textMuted } })}
                    <Typography
                      variant="body2"
                      sx={{
                        fontFamily: '"Share Tech Mono", monospace',
                        color: opt.checked ? CYBER_COLORS.text : CYBER_COLORS.textMuted,
                      }}
                    >
                      {opt.label}
                    </Typography>
                  </Box>
                }
              />
            ))}
          </Box>
        </Grid>
        <Grid item xs={12}>
          {renderAdvancedOptions()}
        </Grid>
        </Grid>
      )}
      {renderManualGuidancePanel()}
    </CyberPaper>
  );
  
  // Render progress panel
  const renderProgress = () => {
    if (!scanResult) return null;
    
    const { progress, status } = scanResult;
    const phaseData = phaseInfo[progress.phase] || { icon: <Memory />, label: progress.phase, color: CYBER_COLORS.textMuted };
    
    return (
      <CyberPaper glowing={isScanning} sx={{ p: 3, mb: 3 }}>
        {/* Scan line animation */}
        {isScanning && (
          <Box
            sx={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 2,
              background: `linear-gradient(90deg, transparent, ${CYBER_COLORS.primary}, transparent)`,
              animation: `${scanLine} 2s ease-in-out infinite`,
            }}
          />
        )}
        
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <Box
            sx={{
              p: 1.5,
              borderRadius: 1,
              bgcolor: alpha(phaseData.color, 0.2),
              border: `1px solid ${phaseData.color}`,
              display: 'flex',
              animation: isScanning ? `${pulseGlow} 1.5s ease-in-out infinite` : 'none',
              boxShadow: `0 0 15px ${alpha(phaseData.color, 0.3)}`,
            }}
          >
            {React.cloneElement(phaseData.icon as React.ReactElement, { sx: { color: phaseData.color } })}
          </Box>
          
          <Box sx={{ flex: 1 }}>
            <Typography
              variant="h6"
              sx={{
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                color: phaseData.color,
                letterSpacing: '0.1em',
              }}
            >
              {phaseData.label}
            </Typography>
            <Typography
              variant="body2"
              sx={{
                fontFamily: '"Share Tech Mono", monospace',
                color: CYBER_COLORS.textMuted,
              }}
            >
              {progress.message}
            </Typography>
          </Box>
          
          <NeonChip
            label={status.toUpperCase()}
            color={status === 'completed' ? 'success' : status === 'running' ? 'primary' : 'warning'}
          />
        </Box>
        
        {/* Progress bar */}
        <Box sx={{ mb: 3 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="caption" sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace' }}>
              PROGRESS
            </Typography>
            <Typography
              variant="caption"
              sx={{
                color: CYBER_COLORS.primary,
                fontFamily: '"Share Tech Mono", monospace',
                fontWeight: 700,
                animation: isScanning ? `${blink} 1s ease-in-out infinite` : 'none',
                textShadow: `0 0 10px ${CYBER_COLORS.glow}`,
              }}
            >
              {progress.overall_progress}%
            </Typography>
          </Box>
          <Box
            sx={{
              height: 12,
              borderRadius: 6,
              bgcolor: alpha(CYBER_COLORS.primary, 0.1),
              border: `1px solid ${alpha(CYBER_COLORS.primary, 0.4)}`,
              overflow: 'hidden',
              position: 'relative',
              boxShadow: `inset 0 2px 4px ${alpha('#000', 0.3)}`,
            }}
          >
            <Box
              sx={{
                height: '100%',
                width: `${progress.overall_progress}%`,
                background: `linear-gradient(90deg, 
                  ${CYBER_COLORS.primaryDark} 0%, 
                  ${CYBER_COLORS.primary} 25%, 
                  ${CYBER_COLORS.accent} 50%, 
                  ${CYBER_COLORS.primary} 75%, 
                  ${CYBER_COLORS.primaryLight} 100%
                )`,
                backgroundSize: '200% 100%',
                animation: `${dataFlow} 1.5s linear infinite`,
                boxShadow: `0 0 20px ${CYBER_COLORS.primary}, 0 0 40px ${alpha(CYBER_COLORS.primary, 0.5)}`,
                transition: 'width 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                position: 'relative',
                '&::after': {
                  content: '""',
                  position: 'absolute',
                  top: 0,
                  right: 0,
                  width: 20,
                  height: '100%',
                  background: `linear-gradient(90deg, transparent, ${CYBER_COLORS.primaryLight})`,
                  filter: 'blur(4px)',
                },
              }}
            />
          </Box>
        </Box>
        
        {/* Stats grid */}
        <Grid container spacing={2}>
          {[
            { icon: <Computer />, value: progress.hosts_discovered, label: 'HOSTS', color: CYBER_COLORS.accent },
            { icon: <Web />, value: progress.web_targets, label: 'WEB TARGETS', color: CYBER_COLORS.info },
            { icon: <Dns />, value: progress.network_targets, label: 'NETWORK', color: CYBER_COLORS.warning },
            { icon: <BugReport />, value: progress.findings_count, label: 'FINDINGS', color: CYBER_COLORS.danger },
          ].map((stat, i) => (
            <Grid item xs={3} key={i}>
              <Box
                sx={{
                  textAlign: 'center',
                  p: 2,
                  borderRadius: 2,
                  bgcolor: alpha(stat.color, 0.08),
                  border: `2px solid ${alpha(stat.color, 0.3)}`,
                  transition: 'all 0.35s cubic-bezier(0.4, 0, 0.2, 1)',
                  cursor: 'pointer',
                  position: 'relative',
                  overflow: 'hidden',
                  animation: isScanning && stat.value > 0 ? `${hackingPulse} 2s ease-in-out infinite` : 'none',
                  animationDelay: `${i * 0.2}s`,
                  '&::before': {
                    content: '""',
                    position: 'absolute',
                    top: '-50%',
                    left: '-50%',
                    width: '200%',
                    height: '200%',
                    background: `conic-gradient(from 0deg, transparent, ${alpha(stat.color, 0.1)}, transparent)`,
                    animation: isScanning ? `${spinGlow} 4s linear infinite` : 'none',
                  },
                  '&:hover': {
                    borderColor: stat.color,
                    boxShadow: `0 0 25px ${alpha(stat.color, 0.4)}, inset 0 0 30px ${alpha(stat.color, 0.1)}`,
                    transform: 'translateY(-4px) scale(1.02)',
                    bgcolor: alpha(stat.color, 0.15),
                  },
                }}
              >
                {React.cloneElement(stat.icon, { 
                  sx: { 
                    fontSize: 36, 
                    color: stat.color, 
                    mb: 1,
                    filter: `drop-shadow(0 0 8px ${stat.color})`,
                    transition: 'transform 0.3s ease',
                  } 
                })}
                <Typography
                  variant="h4"
                  sx={{
                    fontFamily: '"Orbitron", monospace',
                    fontWeight: 700,
                    color: stat.color,
                    textShadow: `0 0 15px ${alpha(stat.color, 0.5)}`,
                  }}
                >
                  {stat.value}
                </Typography>
                <Typography
                  variant="caption"
                  sx={{
                    color: CYBER_COLORS.textMuted,
                    fontFamily: '"Share Tech Mono", monospace',
                    letterSpacing: '0.1em',
                  }}
                >
                  {stat.label}
                </Typography>
              </Box>
            </Grid>
          ))}
        </Grid>
        
        {progress.errors.length > 0 && (
          <Alert
            severity="warning"
            sx={{
              mt: 2,
              bgcolor: alpha(CYBER_COLORS.warning, 0.1),
              border: `1px solid ${CYBER_COLORS.warning}`,
              '& .MuiAlert-icon': { color: CYBER_COLORS.warning },
            }}
          >
            {progress.errors.map((e, i) => <div key={i}>{e}</div>)}
          </Alert>
        )}
      </CyberPaper>
    );
  };
  
  // Deduplicate findings - group by title and severity, count occurrences
  const deduplicateFindings = (findings: DynamicScanFinding[]) => {
    const seen = new Map<string, { finding: DynamicScanFinding; count: number; urls: string[] }>();
    
    for (const finding of findings) {
      // Create a unique key based on title + severity + source
      const key = `${finding.title}|${finding.severity}|${finding.source}`;
      
      if (seen.has(key)) {
        const existing = seen.get(key)!;
        existing.count++;
        if (finding.url && !existing.urls.includes(finding.url)) {
          existing.urls.push(finding.url);
        }
      } else {
        seen.set(key, {
          finding,
          count: 1,
          urls: finding.url ? [finding.url] : [],
        });
      }
    }
    
    return Array.from(seen.values());
  };
  
  // Render Executive Summary - AI-generated comprehensive report
  const renderExecutiveSummary = () => {
    if (!scanResult) return null;
    
    const deduped = deduplicateFindings(scanResult.findings);
    const severityCounts = {
      critical: deduped.filter(f => normalizeSeverity(f.finding.severity) === 'critical').length,
      high: deduped.filter(f => normalizeSeverity(f.finding.severity) === 'high').length,
      medium: deduped.filter(f => normalizeSeverity(f.finding.severity) === 'medium').length,
      low: deduped.filter(f => normalizeSeverity(f.finding.severity) === 'low').length,
      info: deduped.filter(f => normalizeSeverity(f.finding.severity) === 'info').length,
    };
    
    // Calculate risk score (0-100)
    const riskScore = Math.min(100, 
      severityCounts.critical * 25 + 
      severityCounts.high * 15 + 
      severityCounts.medium * 5 + 
      severityCounts.low * 2
    );
    
    const getRiskLevel = (score: number) => {
      if (score >= 75) return { label: 'CRITICAL', color: CYBER_COLORS.danger };
      if (score >= 50) return { label: 'HIGH', color: '#ff6600' };
      if (score >= 25) return { label: 'MEDIUM', color: CYBER_COLORS.warning };
      return { label: 'LOW', color: CYBER_COLORS.success };
    };
    
    const riskLevel = getRiskLevel(riskScore);
    
    // Group findings by source
    const bySource = deduped.reduce((acc, { finding }) => {
      acc[finding.source] = (acc[finding.source] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    
    // Get top vulnerabilities (critical + high)
    const topVulns = deduped
      .filter(f => ['critical', 'high'].includes(normalizeSeverity(f.finding.severity)))
      .slice(0, 5);
    
    return (
      <Box>
        {/* AI Executive Summary - Written Report */}
        {scanResult.executive_summary && (
          <CyberCard sx={{ mb: 3 }}>
            <CardContent>
              <Typography sx={{ 
                color: CYBER_COLORS.secondary, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}>
                <Article /> AI EXECUTIVE SUMMARY
              </Typography>
              <TerminalBox title="executive-summary">
                <Typography sx={{ 
                  color: CYBER_COLORS.text, 
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.9rem',
                  lineHeight: 1.8,
                  whiteSpace: 'pre-wrap',
                }}>
                  {scanResult.executive_summary}
                </Typography>
              </TerminalBox>
            </CardContent>
          </CyberCard>
        )}
        
        {/* No Findings Message - only show when scan is COMPLETED */}
        {deduped.length === 0 && !scanResult.executive_summary && scanResult.status === 'completed' && (
          <CyberCard sx={{ mb: 3 }}>
            <CardContent sx={{ textAlign: 'center', py: 4 }}>
              <GppGood sx={{ fontSize: 80, color: CYBER_COLORS.success, mb: 2 }} />
              <Typography sx={{ 
                color: CYBER_COLORS.success, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                fontSize: '1.5rem',
                mb: 2,
              }}>
                NO VULNERABILITIES DETECTED
              </Typography>
              <Typography sx={{ 
                color: CYBER_COLORS.textMuted, 
                fontFamily: '"Share Tech Mono", monospace',
                fontSize: '0.95rem',
                maxWidth: 600,
                mx: 'auto',
              }}>
                The security scan completed without finding any vulnerabilities. 
                This is a positive result, but remember that no automated scan can 
                guarantee complete security. Consider manual penetration testing for 
                comprehensive coverage.
              </Typography>
            </CardContent>
          </CyberCard>
        )}
        
        {/* Scan In Progress Message */}
        {deduped.length === 0 && !scanResult.executive_summary && scanResult.status !== 'completed' && (
          <CyberCard sx={{ mb: 3 }}>
            <CardContent sx={{ textAlign: 'center', py: 4 }}>
              <CircularProgress size={60} sx={{ color: CYBER_COLORS.primary, mb: 2 }} />
              <Typography sx={{ 
                color: CYBER_COLORS.primary, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                fontSize: '1.5rem',
                mb: 2,
              }}>
                SCAN IN PROGRESS
              </Typography>
              <Typography sx={{ 
                color: CYBER_COLORS.textMuted, 
                fontFamily: '"Share Tech Mono", monospace',
                fontSize: '0.95rem',
                maxWidth: 600,
                mx: 'auto',
              }}>
                The security scan is currently running. Results will appear here 
                once scanning is complete. This may take several minutes depending 
                on the target complexity.
              </Typography>
            </CardContent>
          </CyberCard>
        )}
        
        {/* Risk Overview Section */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          {/* Risk Score */}
          <Grid item xs={12} md={4}>
            <CyberCard sx={{ height: '100%', textAlign: 'center', py: 3 }}>
              <Typography sx={{ 
                color: CYBER_COLORS.textMuted, 
                fontFamily: '"Share Tech Mono", monospace',
                letterSpacing: '0.2em',
                mb: 2,
              }}>
                OVERALL RISK SCORE
              </Typography>
              <Box sx={{ position: 'relative', display: 'inline-block' }}>
                <CircularProgress
                  variant="determinate"
                  value={riskScore}
                  size={120}
                  thickness={4}
                  sx={{
                    color: riskLevel.color,
                    '& .MuiCircularProgress-circle': {
                      filter: `drop-shadow(0 0 10px ${riskLevel.color})`,
                    },
                  }}
                />
                <Box sx={{
                  position: 'absolute',
                  top: '50%',
                  left: '50%',
                  transform: 'translate(-50%, -50%)',
                  textAlign: 'center',
                }}>
                  <Typography sx={{ 
                    color: riskLevel.color,
                    fontFamily: '"Orbitron", monospace',
                    fontSize: '2rem',
                    fontWeight: 700,
                  }}>
                    {riskScore}
                  </Typography>
                </Box>
              </Box>
              <Typography sx={{ 
                color: riskLevel.color, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                fontSize: '1.2rem',
                mt: 2,
                textShadow: `0 0 10px ${riskLevel.color}`,
              }}>
                {riskLevel.label} RISK
              </Typography>
            </CyberCard>
          </Grid>
          
          {/* Vulnerability Breakdown */}
          <Grid item xs={12} md={4}>
            <CyberCard sx={{ height: '100%' }}>
              <Typography sx={{ 
                color: CYBER_COLORS.textMuted, 
                fontFamily: '"Share Tech Mono", monospace',
                letterSpacing: '0.2em',
                mb: 2,
                textAlign: 'center',
              }}>
                VULNERABILITY BREAKDOWN
              </Typography>
              <Box sx={{ px: 2 }}>
                {[
                  { label: 'CRITICAL', count: severityCounts.critical, color: CYBER_COLORS.danger },
                  { label: 'HIGH', count: severityCounts.high, color: '#ff6600' },
                  { label: 'MEDIUM', count: severityCounts.medium, color: CYBER_COLORS.warning },
                  { label: 'LOW', count: severityCounts.low, color: CYBER_COLORS.info },
                  { label: 'INFO', count: severityCounts.info, color: CYBER_COLORS.textMuted },
                ].map((item) => (
                  <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', mb: 1.5 }}>
                    <Typography sx={{ 
                      color: item.color, 
                      fontFamily: '"Share Tech Mono", monospace',
                      width: 80,
                      fontSize: '0.85rem',
                    }}>
                      {item.label}
                    </Typography>
                    <Box sx={{ 
                      flex: 1, 
                      height: 8, 
                      bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                      borderRadius: 1,
                      overflow: 'hidden',
                      mx: 1,
                    }}>
                      <Box sx={{ 
                        width: `${Math.min(100, item.count * 10)}%`,
                        height: '100%',
                        bgcolor: item.color,
                        boxShadow: `0 0 10px ${item.color}`,
                      }} />
                    </Box>
                    <Typography sx={{ 
                      color: item.color, 
                      fontFamily: '"Orbitron", monospace',
                      width: 30,
                      textAlign: 'right',
                    }}>
                      {item.count}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CyberCard>
          </Grid>
          
          {/* Scan Statistics */}
          <Grid item xs={12} md={4}>
            <CyberCard sx={{ height: '100%' }}>
              <Typography sx={{ 
                color: CYBER_COLORS.textMuted, 
                fontFamily: '"Share Tech Mono", monospace',
                letterSpacing: '0.2em',
                mb: 2,
                textAlign: 'center',
              }}>
                SCAN STATISTICS
              </Typography>
              <Box sx={{ px: 2 }}>
                {[
                  { label: 'Target', value: scanResult.target },
                  { label: 'Hosts Discovered', value: scanResult.hosts.length },
                  { label: 'Web Targets', value: scanResult.web_targets.length },
                  { label: 'Unique Findings', value: deduped.length },
                  { label: 'Total Instances', value: scanResult.findings.length },
                  { label: 'Duration', value: scanResult.duration_seconds ? `${Math.floor(scanResult.duration_seconds / 60)}m ${scanResult.duration_seconds % 60}s` : 'N/A' },
                ].map((item, idx) => (
                  <Box key={idx} sx={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    py: 1,
                    borderBottom: idx < 5 ? `1px solid ${alpha(CYBER_COLORS.primary, 0.1)}` : 'none',
                  }}>
                    <Typography sx={{ 
                      color: CYBER_COLORS.textMuted, 
                      fontFamily: '"Share Tech Mono", monospace',
                      fontSize: '0.85rem',
                    }}>
                      {item.label}
                    </Typography>
                    <Typography sx={{ 
                      color: CYBER_COLORS.accent, 
                      fontFamily: '"Share Tech Mono", monospace',
                      fontSize: '0.85rem',
                    }}>
                      {item.value}
                    </Typography>
                  </Box>
                ))}
              </Box>
            </CyberCard>
          </Grid>
        </Grid>
        
        {/* Top Critical Vulnerabilities */}
        {topVulns.length > 0 && (
          <CyberCard sx={{ mb: 3 }}>
            <CardContent>
              <Typography sx={{ 
                color: CYBER_COLORS.danger, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}>
                <GppBad /> TOP CRITICAL/HIGH VULNERABILITIES
              </Typography>
              <TableContainer sx={{ bgcolor: alpha(CYBER_COLORS.dark, 0.5), borderRadius: 1 }}>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      {['SEVERITY', 'VULNERABILITY', 'SOURCE', 'INSTANCES'].map(h => (
                        <TableCell key={h} sx={{ 
                          color: CYBER_COLORS.primary, 
                          fontFamily: '"Share Tech Mono", monospace',
                          borderColor: alpha(CYBER_COLORS.primary, 0.2),
                        }}>
                          {h}
                        </TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {topVulns.map(({ finding, count }, idx) => (
                      <TableRow key={idx}>
                        <TableCell sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.1) }}>
                          <NeonChip label={formatSeverity(finding.severity)} color={normalizeSeverity(finding.severity)} />
                        </TableCell>
                        <TableCell sx={{ 
                          color: CYBER_COLORS.text, 
                          fontFamily: '"Share Tech Mono", monospace',
                          borderColor: alpha(CYBER_COLORS.primary, 0.1),
                        }}>
                          {finding.title}
                        </TableCell>
                        <TableCell sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.1) }}>
                          <NeonChip label={finding.source.toUpperCase()} color="info" />
                        </TableCell>
                        <TableCell sx={{ 
                          color: CYBER_COLORS.warning, 
                          fontFamily: '"Orbitron", monospace',
                          borderColor: alpha(CYBER_COLORS.primary, 0.1),
                        }}>
                          {count}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </CyberCard>
        )}
        
        {/* AI Attack Narrative Summary */}
        {scanResult.attack_narrative && (
          <CyberCard sx={{ mb: 3 }}>
            <CardContent>
              <Typography sx={{ 
                color: CYBER_COLORS.secondary, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}>
                <Psychology /> AI ATTACK ANALYSIS
              </Typography>
              <TerminalBox title="threat-assessment">
                <Typography sx={{ 
                  color: CYBER_COLORS.text, 
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.9rem',
                  lineHeight: 1.8,
                  whiteSpace: 'pre-wrap',
                }}>
                  {scanResult.attack_narrative}
                </Typography>
              </TerminalBox>
            </CardContent>
          </CyberCard>
        )}
        
        {/* Recommendations */}
        {scanResult.recommendations.length > 0 && (
          <CyberCard>
            <CardContent>
              <Typography sx={{ 
                color: CYBER_COLORS.success, 
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}>
                <GppGood /> SECURITY RECOMMENDATIONS
              </Typography>
              <List>
                {scanResult.recommendations.map((rec, idx) => (
                  <ListItem key={idx} sx={{ 
                    py: 1,
                    borderBottom: idx < scanResult.recommendations.length - 1 
                      ? `1px solid ${alpha(CYBER_COLORS.primary, 0.1)}` 
                      : 'none',
                  }}>
                    <ListItemIcon>
                      <Shield sx={{ color: CYBER_COLORS.success }} />
                    </ListItemIcon>
                    <ListItemText 
                      primary={rec}
                      primaryTypographyProps={{
                        sx: { 
                          color: CYBER_COLORS.text, 
                          fontFamily: '"Share Tech Mono", monospace',
                          fontSize: '0.9rem',
                        },
                      }}
                    />
                  </ListItem>
                ))}
              </List>
            </CardContent>
          </CyberCard>
        )}
        
        {/* Scanner Sources */}
        <Box sx={{ mt: 3 }}>
          <Typography sx={{ 
            color: CYBER_COLORS.textMuted, 
            fontFamily: '"Share Tech Mono", monospace',
            letterSpacing: '0.1em',
            mb: 2,
          }}>
            FINDINGS BY SCANNER SOURCE
          </Typography>
          <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
            {Object.entries(bySource).map(([source, count]) => (
              <CyberCard key={source} sx={{ px: 3, py: 2 }}>
                <Typography sx={{ 
                  color: CYBER_COLORS.primary, 
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.85rem',
                }}>
                  {source.toUpperCase()}
                </Typography>
                <Typography sx={{ 
                  color: CYBER_COLORS.accent, 
                  fontFamily: '"Orbitron", monospace',
                  fontSize: '1.5rem',
                  fontWeight: 700,
                }}>
                  {count}
                </Typography>
              </CyberCard>
            ))}
          </Box>
        </Box>
      </Box>
    );
  };
  
  // Render findings
  const renderFindings = () => {
    if (!scanResult?.findings.length) {
      return (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <BugReport sx={{ fontSize: 60, color: CYBER_COLORS.textMuted, mb: 2 }} />
          <Typography sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace' }}>
            NO VULNERABILITIES DETECTED
          </Typography>
        </Box>
      );
    }
    
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const deduped = deduplicateFindings(scanResult.findings);
    const sortedFindings = deduped.sort(
      (a, b) => severityOrder.indexOf(normalizeSeverity(a.finding.severity)) - severityOrder.indexOf(normalizeSeverity(b.finding.severity))
    );
    
    // Calculate severity counts for summary
    const severityCounts = {
      critical: sortedFindings.filter(f => normalizeSeverity(f.finding.severity) === 'critical').length,
      high: sortedFindings.filter(f => normalizeSeverity(f.finding.severity) === 'high').length,
      medium: sortedFindings.filter(f => normalizeSeverity(f.finding.severity) === 'medium').length,
      low: sortedFindings.filter(f => normalizeSeverity(f.finding.severity) === 'low').length,
      info: sortedFindings.filter(f => normalizeSeverity(f.finding.severity) === 'info').length,
    };
    
    return (
      <Box>
        {/* Quick Stats */}
        <Box sx={{ 
          display: 'flex', 
          gap: 2, 
          mb: 3, 
          p: 2, 
          bgcolor: alpha(CYBER_COLORS.dark, 0.5),
          borderRadius: 1,
          border: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
        }}>
          <Typography sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace', mr: 2 }}>
            UNIQUE FINDINGS: {sortedFindings.length} ({scanResult.findings.length} total instances)
          </Typography>
          {severityCounts.critical > 0 && <NeonChip label={`${severityCounts.critical} CRITICAL`} color="critical" />}
          {severityCounts.high > 0 && <NeonChip label={`${severityCounts.high} HIGH`} color="high" />}
          {severityCounts.medium > 0 && <NeonChip label={`${severityCounts.medium} MEDIUM`} color="medium" />}
          {severityCounts.low > 0 && <NeonChip label={`${severityCounts.low} LOW`} color="low" />}
          {severityCounts.info > 0 && <NeonChip label={`${severityCounts.info} INFO`} color="info" />}
        </Box>
        
        {sortedFindings.map(({ finding, count, urls }, index) => (
          <CyberCard key={index} severity={finding.severity} sx={{ mb: 2 }}>
            <Accordion
              expanded={expandedFinding === index}
              onChange={() => {
                setExpandedFinding(expandedFinding === index ? null : index);
                setFindingExplanation(null);
              }}
              sx={{ bgcolor: 'transparent', boxShadow: 'none' }}
            >
              <AccordionSummary
                expandIcon={<ExpandMore sx={{ color: CYBER_COLORS.textMuted }} />}
                sx={{ px: 2 }}
              >
                <Box sx={{ display: 'flex', alignItems: 'center', width: '100%', gap: 2 }}>
                  {getSeverityIcon(finding.severity)}
                  <NeonChip label={formatSeverity(finding.severity)} color={normalizeSeverity(finding.severity)} />
                  <Typography
                    sx={{
                      flex: 1,
                      fontFamily: '"Rajdhani", sans-serif',
                      fontWeight: 600,
                      color: CYBER_COLORS.text,
                    }}
                  >
                    {finding.title}
                    {count > 1 && (
                      <Typography component="span" sx={{ 
                        ml: 1, 
                        color: CYBER_COLORS.warning,
                        fontFamily: '"Share Tech Mono", monospace',
                        fontSize: '0.85rem',
                      }}>
                        ({count} instances)
                      </Typography>
                    )}
                  </Typography>
                  <NeonChip label={finding.source.toUpperCase()} color="info" />
                  {finding.exploit_available && (
                    <NeonChip label="⚡ EXPLOIT" color="danger" />
                  )}
                </Box>
              </AccordionSummary>
              <AccordionDetails sx={{ px: 2 }}>
                <Grid container spacing={2}>
                  <Grid item xs={12} md={6}>
                    <TerminalBox title="target">
                      <Typography
                        sx={{
                          fontFamily: '"Share Tech Mono", monospace',
                          color: CYBER_COLORS.accent,
                        }}
                      >
                        {finding.host}{finding.port ? `:${finding.port}` : ''}
                      </Typography>
                      {finding.url && (
                        <Typography
                          sx={{
                            fontFamily: '"Share Tech Mono", monospace',
                            color: CYBER_COLORS.textMuted,
                            fontSize: '0.85rem',
                          }}
                        >
                          {finding.url}
                        </Typography>
                      )}
                    </TerminalBox>
                  </Grid>
                  
                  {finding.cve_id && (
                    <Grid item xs={12} md={6}>
                      <TerminalBox title="cve">
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                          <NeonChip label={finding.cve_id} color="danger" />
                          {finding.cvss_score && (
                            <Typography sx={{ color: CYBER_COLORS.warning, fontFamily: '"Orbitron", monospace' }}>
                              CVSS: {finding.cvss_score}
                            </Typography>
                          )}
                        </Box>
                      </TerminalBox>
                    </Grid>
                  )}
                  
                  <Grid item xs={12}>
                    <TerminalBox title="description">
                      <Typography
                        sx={{
                          color: CYBER_COLORS.text,
                          fontFamily: '"Share Tech Mono", monospace',
                          fontSize: '0.9rem',
                          lineHeight: 1.6,
                        }}
                      >
                        {finding.description || 'No description available'}
                      </Typography>
                    </TerminalBox>
                  </Grid>
                  
                  {finding.evidence && (
                    <Grid item xs={12}>
                      <TerminalBox title="evidence">
                        <Typography
                          component="pre"
                          sx={{
                            color: CYBER_COLORS.accent,
                            fontFamily: '"Share Tech Mono", monospace',
                            fontSize: '0.85rem',
                            whiteSpace: 'pre-wrap',
                            m: 0,
                          }}
                        >
                          {finding.evidence}
                        </Typography>
                      </TerminalBox>
                    </Grid>
                  )}
                  
                  {finding.exploit_info && (finding.exploit_info as any).msf_module && (
                    <Grid item xs={12}>
                      <TerminalBox title="metasploit">
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography
                            sx={{
                              flex: 1,
                              color: CYBER_COLORS.danger,
                              fontFamily: '"Share Tech Mono", monospace',
                            }}
                          >
                            use {(finding.exploit_info as any).msf_module}
                          </Typography>
                          <IconButton
                            size="small"
                            onClick={() => handleCopyCommand(`use ${(finding.exploit_info as any).msf_module}\nset RHOSTS ${finding.host}\nrun`)}
                            sx={{ color: CYBER_COLORS.primary }}
                          >
                            <ContentCopy fontSize="small" />
                          </IconButton>
                        </Box>
                      </TerminalBox>
                    </Grid>
                  )}
                  
                  {/* Show affected URLs if there are multiple instances */}
                  {urls.length > 1 && (
                    <Grid item xs={12}>
                      <TerminalBox title={`affected-urls (${urls.length})`}>
                        <Box sx={{ maxHeight: 200, overflow: 'auto' }}>
                          {urls.map((url, urlIdx) => (
                            <Typography
                              key={urlIdx}
                              sx={{
                                color: CYBER_COLORS.textMuted,
                                fontFamily: '"Share Tech Mono", monospace',
                                fontSize: '0.8rem',
                                py: 0.5,
                                borderBottom: urlIdx < urls.length - 1 ? `1px solid ${alpha(CYBER_COLORS.primary, 0.1)}` : 'none',
                              }}
                            >
                              {url}
                            </Typography>
                          ))}
                        </Box>
                      </TerminalBox>
                    </Grid>
                  )}
                  
                  {finding.remediation && (
                    <Grid item xs={12}>
                      <TerminalBox title="remediation">
                        <Typography
                          sx={{
                            color: CYBER_COLORS.success,
                            fontFamily: '"Share Tech Mono", monospace',
                            fontSize: '0.9rem',
                          }}
                        >
                          {finding.remediation}
                        </Typography>
                      </TerminalBox>
                    </Grid>
                  )}
                  
                  <Grid item xs={12}>
                    <CyberButton
                      variant="outlined"
                      size="small"
                      startIcon={loadingExplanation ? <CircularProgress size={16} /> : <Psychology />}
                      onClick={() => handleExplainFinding(index)}
                      disabled={loadingExplanation}
                    >
                      AI ANALYSIS
                    </CyberButton>
                    
                    {findingExplanation && expandedFinding === index && (
                      <TerminalBox title="ai-analysis" sx={{ mt: 2 }}>
                        <Typography
                          sx={{
                            color: CYBER_COLORS.secondary,
                            fontFamily: '"Share Tech Mono", monospace',
                            fontSize: '0.9rem',
                            whiteSpace: 'pre-wrap',
                            lineHeight: 1.6,
                          }}
                        >
                          {findingExplanation}
                        </Typography>
                      </TerminalBox>
                    )}
                  </Grid>
                </Grid>
              </AccordionDetails>
            </Accordion>
          </CyberCard>
        ))}
      </Box>
    );
  };
  
  // Render attack narrative
  const renderNarrative = () => {
    if (!scanResult?.attack_narrative) {
      return (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Psychology sx={{ fontSize: 60, color: CYBER_COLORS.textMuted, mb: 2 }} />
          <Typography sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace' }}>
            ATTACK NARRATIVE PENDING...
          </Typography>
        </Box>
      );
    }
    
    return (
      <Box>
        <TerminalBox title="attack-narrative" sx={{ mb: 3 }}>
          <Typography
            sx={{
              color: CYBER_COLORS.danger,
              fontFamily: '"Share Tech Mono", monospace',
              fontSize: '0.95rem',
              lineHeight: 1.8,
              whiteSpace: 'pre-wrap',
            }}
          >
            {scanResult.attack_narrative}
          </Typography>
        </TerminalBox>
        
        {scanResult.exploit_chains.length > 0 && (
          <Box sx={{ mb: 3 }}>
            <Typography
              variant="h6"
              sx={{
                color: CYBER_COLORS.danger,
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}
            >
              <Fingerprint /> EXPLOIT CHAINS
            </Typography>
            {scanResult.exploit_chains.map((chain, index) => (
              <CyberCard key={index} severity="high" sx={{ mb: 2 }}>
                <CardContent>
                  <Typography
                    variant="h6"
                    sx={{
                      color: CYBER_COLORS.text,
                      fontFamily: '"Rajdhani", sans-serif',
                      fontWeight: 600,
                    }}
                  >
                    {chain.name}
                  </Typography>
                  <Typography
                    sx={{
                      color: CYBER_COLORS.textMuted,
                      fontFamily: '"Share Tech Mono", monospace',
                      fontSize: '0.9rem',
                      my: 1,
                    }}
                  >
                    {chain.description}
                  </Typography>
                  
                  <Box sx={{ mt: 2 }}>
                    {chain.steps.map((step, i) => (
                      <Box
                        key={i}
                        sx={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 2,
                          py: 1,
                          borderLeft: `2px solid ${CYBER_COLORS.primary}`,
                          pl: 2,
                          ml: 1,
                        }}
                      >
                        <NeonChip label={`${i + 1}`} color="primary" sx={{ minWidth: 30 }} />
                        <Typography
                          sx={{
                            color: CYBER_COLORS.text,
                            fontFamily: '"Share Tech Mono", monospace',
                            fontSize: '0.9rem',
                          }}
                        >
                          {step}
                        </Typography>
                      </Box>
                    ))}
                  </Box>
                  
                  <Box sx={{ display: 'flex', gap: 1, mt: 2 }}>
                    <NeonChip label={`IMPACT: ${chain.impact}`} color="danger" />
                    <NeonChip label={`LIKELIHOOD: ${chain.likelihood}`} color="warning" />
                  </Box>
                </CardContent>
              </CyberCard>
            ))}
          </Box>
        )}
        
        {scanResult.recommendations.length > 0 && (
          <Box>
            <Typography
              variant="h6"
              sx={{
                color: CYBER_COLORS.success,
                fontFamily: '"Rajdhani", sans-serif',
                fontWeight: 700,
                letterSpacing: '0.1em',
                mb: 2,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}
            >
              <GppGood /> RECOMMENDATIONS
            </Typography>
            <List>
              {scanResult.recommendations.map((rec, index) => (
                <ListItem
                  key={index}
                  sx={{
                    bgcolor: alpha(CYBER_COLORS.success, 0.1),
                    border: `1px solid ${alpha(CYBER_COLORS.success, 0.3)}`,
                    borderRadius: 1,
                    mb: 1,
                  }}
                >
                  <ListItemIcon>
                    <CheckCircle sx={{ color: CYBER_COLORS.success }} />
                  </ListItemIcon>
                  <ListItemText
                    primary={rec}
                    sx={{
                      '& .MuiListItemText-primary': {
                        color: CYBER_COLORS.text,
                        fontFamily: '"Share Tech Mono", monospace',
                      },
                    }}
                  />
                </ListItem>
              ))}
            </List>
          </Box>
        )}
      </Box>
    );
  };
  
  // Render commands
  const renderCommands = () => {
    if (!scanResult?.exploit_commands || Object.keys(scanResult.exploit_commands).length === 0) {
      return (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Terminal sx={{ fontSize: 60, color: CYBER_COLORS.textMuted, mb: 2 }} />
          <Typography sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace' }}>
            NO EXPLOITATION COMMANDS GENERATED
          </Typography>
        </Box>
      );
    }
    
    return (
      <Box>
        {Object.entries(scanResult.exploit_commands).map(([tool, commands]) => (
          <Accordion
            key={tool}
            defaultExpanded={tool === 'metasploit'}
            sx={{
              bgcolor: alpha(CYBER_COLORS.dark, 0.5),
              border: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
              mb: 2,
              '&::before': { display: 'none' },
            }}
          >
            <AccordionSummary expandIcon={<ExpandMore sx={{ color: CYBER_COLORS.textMuted }} />}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Terminal sx={{ color: CYBER_COLORS.primary }} />
                <Typography
                  sx={{
                    fontFamily: '"Rajdhani", sans-serif',
                    fontWeight: 700,
                    color: CYBER_COLORS.text,
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em',
                  }}
                >
                  {tool}
                </Typography>
                <NeonChip label={`${commands.length} COMMANDS`} color="primary" />
              </Box>
            </AccordionSummary>
            <AccordionDetails>
              {commands.map((cmd, index) => (
                <TerminalBox key={index} title={`command-${index + 1}`} sx={{ mb: 2 }}>
                  <Box sx={{ position: 'relative' }}>
                    <IconButton
                      size="small"
                      onClick={() => handleCopyCommand(cmd)}
                      sx={{
                        position: 'absolute',
                        top: -8,
                        right: -8,
                        color: copiedCommand === cmd ? CYBER_COLORS.success : CYBER_COLORS.primary,
                      }}
                    >
                      {copiedCommand === cmd ? <CheckCircle /> : <ContentCopy />}
                    </IconButton>
                    <Typography
                      component="pre"
                      sx={{
                        fontFamily: '"Share Tech Mono", monospace',
                        fontSize: '0.85rem',
                        color: CYBER_COLORS.accent,
                        whiteSpace: 'pre-wrap',
                        m: 0,
                        pr: 4,
                      }}
                    >
                      {cmd}
                    </Typography>
                  </Box>
                </TerminalBox>
              ))}
            </AccordionDetails>
          </Accordion>
        ))}
      </Box>
    );
  };
  
  // Render hosts
  const renderHosts = () => {
    if (!scanResult?.hosts.length) {
      return (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Computer sx={{ fontSize: 60, color: CYBER_COLORS.textMuted, mb: 2 }} />
          <Typography sx={{ color: CYBER_COLORS.textMuted, fontFamily: '"Share Tech Mono", monospace' }}>
            NO HOSTS DISCOVERED
          </Typography>
        </Box>
      );
    }
    
    return (
      <Grid container spacing={2}>
        {scanResult.hosts.map((host, index) => (
          <Grid item xs={12} md={6} key={index}>
            <CyberCard>
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                  <Computer sx={{ color: CYBER_COLORS.accent, fontSize: 32 }} />
                  <Box>
                    <Typography
                      variant="h6"
                      sx={{
                        fontFamily: '"Orbitron", monospace',
                        color: CYBER_COLORS.accent,
                      }}
                    >
                      {host.ip}
                    </Typography>
                    {host.hostname && (
                      <Typography
                        sx={{
                          color: CYBER_COLORS.textMuted,
                          fontFamily: '"Share Tech Mono", monospace',
                          fontSize: '0.85rem',
                        }}
                      >
                        {host.hostname}
                      </Typography>
                    )}
                  </Box>
                </Box>
                
                {host.os && <NeonChip label={host.os} color="info" sx={{ mb: 2 }} />}
                
                <Typography
                  variant="subtitle2"
                  sx={{
                    color: CYBER_COLORS.textMuted,
                    fontFamily: '"Share Tech Mono", monospace',
                    letterSpacing: '0.1em',
                    mb: 1,
                  }}
                >
                  OPEN PORTS ({host.ports.filter(p => p.state === 'open').length})
                </Typography>
                
                <TableContainer
                  sx={{
                    bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                    borderRadius: 1,
                    border: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
                  }}
                >
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        {['PORT', 'SERVICE', 'VERSION'].map((h) => (
                          <TableCell
                            key={h}
                            sx={{
                              color: CYBER_COLORS.primary,
                              fontFamily: '"Share Tech Mono", monospace',
                              borderColor: alpha(CYBER_COLORS.primary, 0.2),
                            }}
                          >
                            {h}
                          </TableCell>
                        ))}
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {host.ports.filter(p => p.state === 'open').slice(0, 10).map((port, i) => (
                        <TableRow key={i}>
                          <TableCell
                            sx={{
                              color: CYBER_COLORS.accent,
                              fontFamily: '"Share Tech Mono", monospace',
                              borderColor: alpha(CYBER_COLORS.primary, 0.1),
                            }}
                          >
                            {port.port}/{port.protocol}
                          </TableCell>
                          <TableCell
                            sx={{
                              color: CYBER_COLORS.text,
                              fontFamily: '"Share Tech Mono", monospace',
                              borderColor: alpha(CYBER_COLORS.primary, 0.1),
                            }}
                          >
                            {port.service || '-'}
                          </TableCell>
                          <TableCell
                            sx={{
                              color: CYBER_COLORS.textMuted,
                              fontFamily: '"Share Tech Mono", monospace',
                              borderColor: alpha(CYBER_COLORS.primary, 0.1),
                            }}
                          >
                            {port.product} {port.version}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              </CardContent>
            </CyberCard>
          </Grid>
        ))}
      </Grid>
    );
  };
  
  // Render empty state
  const renderEmptyState = () => (
    <CyberPaper sx={{ p: 6, textAlign: 'center' }}>
      <Box
        sx={{
          position: 'relative',
          width: 120,
          height: 120,
          mx: 'auto',
          mb: 3,
        }}
      >
        <Box
          sx={{
            position: 'absolute',
            width: '100%',
            height: '100%',
            borderRadius: '50%',
            border: `2px dashed ${alpha(CYBER_COLORS.primary, 0.3)}`,
            animation: `${radarSweep} 10s linear infinite`,
          }}
        />
        <Box
          sx={{
            position: 'absolute',
            top: '50%',
            left: '50%',
            transform: 'translate(-50%, -50%)',
          }}
        >
          <Radar sx={{ fontSize: 60, color: CYBER_COLORS.primary }} />
        </Box>
      </Box>
      
      <GlitchText variant="h5" sx={{ mb: 2 }}>
        AWAITING TARGET
      </GlitchText>
      
      <Typography
        sx={{
          color: CYBER_COLORS.textMuted,
          fontFamily: '"Share Tech Mono", monospace',
          maxWidth: 500,
          mx: 'auto',
          mb: 3,
        }}
      >
        Initialize target parameters and engage the automated pentesting framework.
        The AI will orchestrate Nmap reconnaissance, service routing, vulnerability scanning,
        and exploit mapping.
      </Typography>
      
      <Box sx={{ display: 'flex', justifyContent: 'center', gap: 2, flexWrap: 'wrap' }}>
        {['RECONNAISSANCE', 'CVE DETECTION', 'EXPLOIT MAPPING', 'AI ANALYSIS'].map((step, i) => (
          <NeonChip key={i} label={`${i + 1}. ${step}`} color="primary" />
        ))}
      </Box>
    </CyberPaper>
  );
  
  // ============================================================================
  // MAIN RENDER
  // ============================================================================
  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: CYBER_COLORS.dark,
        p: 3,
        position: 'relative',
        overflow: 'hidden',
        '&::before': {
          content: '""',
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: `
            radial-gradient(ellipse at 20% 80%, ${alpha(CYBER_COLORS.primary, 0.08)} 0%, transparent 50%),
            radial-gradient(ellipse at 80% 20%, ${alpha(CYBER_COLORS.accent, 0.06)} 0%, transparent 50%),
            radial-gradient(ellipse at 50% 50%, ${alpha(CYBER_COLORS.secondary, 0.04)} 0%, transparent 70%),
            repeating-linear-gradient(
              0deg,
              transparent,
              transparent 2px,
              ${alpha(CYBER_COLORS.primary, 0.02)} 2px,
              ${alpha(CYBER_COLORS.primary, 0.02)} 4px
            )
          `,
          pointerEvents: 'none',
          zIndex: 0,
        },
        '&::after': {
          content: '""',
          position: 'fixed',
          top: '-50%',
          left: '-50%',
          right: '-50%',
          bottom: '-50%',
          background: `
            radial-gradient(circle at 50% 50%, transparent 0%, ${CYBER_COLORS.dark} 70%),
            url("data:image/svg+xml,%3Csvg viewBox='0 0 400 400' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)'/%3E%3C/svg%3E")
          `,
          opacity: 0.03,
          pointerEvents: 'none',
          zIndex: 0,
        },
      }}
    >
      {/* Matrix Rain Effect */}
      {isScanning && (
        <Box
          sx={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            pointerEvents: 'none',
            zIndex: 0,
            overflow: 'hidden',
            '&::before': {
              content: '""',
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: '200%',
              background: `repeating-linear-gradient(
                0deg,
                transparent 0px,
                ${alpha(CYBER_COLORS.primary, 0.03)} 1px,
                transparent 2px,
                transparent 20px
              )`,
              animation: `${matrixRain} 20s linear infinite`,
            },
          }}
        />
      )}
      
      <Box sx={{ maxWidth: 1400, mx: 'auto', position: 'relative', zIndex: 1 }}>
        {renderHeader()}
        {renderConfig()}
        
        {error && (
          <Alert
            severity="error"
            onClose={() => setError(null)}
            sx={{
              mb: 3,
              bgcolor: alpha(CYBER_COLORS.danger, 0.1),
              border: `1px solid ${CYBER_COLORS.danger}`,
              '& .MuiAlert-icon': { color: CYBER_COLORS.danger },
            }}
          >
            {error}
          </Alert>
        )}
        
        {scanResult && renderProgress()}
        
        {scanResult ? (
          <CyberPaper sx={{ p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Tabs
                value={activeTab}
                onChange={(_, v) => setActiveTab(v)}
                sx={{
                  '& .MuiTab-root': {
                    color: CYBER_COLORS.textMuted,
                    fontFamily: '"Orbitron", "Rajdhani", sans-serif',
                    fontWeight: 600,
                    letterSpacing: '0.1em',
                    textTransform: 'uppercase',
                    minHeight: 48,
                    transition: 'all 0.3s ease',
                    position: 'relative',
                    '&::after': {
                      content: '""',
                      position: 'absolute',
                      bottom: 0,
                      left: '50%',
                      width: 0,
                      height: 2,
                      bgcolor: CYBER_COLORS.primary,
                      transition: 'all 0.3s ease',
                      transform: 'translateX(-50%)',
                    },
                    '&:hover': {
                      color: CYBER_COLORS.primary,
                      textShadow: `0 0 10px ${CYBER_COLORS.glow}`,
                      '&::after': {
                        width: '80%',
                        boxShadow: `0 0 10px ${CYBER_COLORS.primary}`,
                      },
                    },
                    '&.Mui-selected': {
                      color: CYBER_COLORS.primary,
                      textShadow: `0 0 15px ${CYBER_COLORS.glow}`,
                    },
                  },
                  '& .MuiTabs-indicator': {
                    bgcolor: CYBER_COLORS.primary,
                    height: 3,
                    boxShadow: `0 0 15px ${CYBER_COLORS.primary}, 0 0 30px ${CYBER_COLORS.glow}`,
                    borderRadius: 1,
                  },
                }}
              >
                <Tab label="📊 EXECUTIVE SUMMARY" />
                <Tab
                  label={
                    <Badge badgeContent={deduplicateFindings(scanResult.findings).length} color="error">
                      <Box sx={{ pr: 2 }}>FINDINGS</Box>
                    </Badge>
                  }
                />
                <Tab label="ATTACK NARRATIVE" />
                <Tab label="COMMANDS" />
                <Tab label="HOSTS" />
              </Tabs>
              
              <Box sx={{ display: 'flex', gap: 1 }}>
                <Tooltip title="Export JSON">
                  <IconButton onClick={() => handleExport('json')} sx={{ color: CYBER_COLORS.primary }}>
                    <DataObject />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Export Markdown">
                  <IconButton onClick={() => handleExport('markdown')} sx={{ color: CYBER_COLORS.primary }}>
                    <Article />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Export PDF">
                  <IconButton onClick={() => handleExport('pdf' as any)} sx={{ color: CYBER_COLORS.warning }}>
                    <Download />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Export Word">
                  <IconButton onClick={() => handleExport('docx' as any)} sx={{ color: CYBER_COLORS.info }}>
                    <Download />
                  </IconButton>
                </Tooltip>
              </Box>
            </Box>
            
            <Box sx={{ p: 2 }}>
              {activeTab === 0 && renderExecutiveSummary()}
              {activeTab === 1 && renderFindings()}
              {activeTab === 2 && renderNarrative()}
              {activeTab === 3 && renderCommands()}
              {activeTab === 4 && renderHosts()}
            </Box>
          </CyberPaper>
        ) : !isScanning && (
          renderEmptyState()
        )}
        
        {/* Saved Scans Section */}
        {savedScans.length > 0 && (
          <CyberPaper sx={{ mt: 3 }}>
            <Box sx={{ 
              p: 2, 
              borderBottom: `1px solid ${alpha(CYBER_COLORS.primary, 0.2)}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <Typography variant="h6" sx={{ 
                color: CYBER_COLORS.primary, 
                fontFamily: '"Share Tech Mono", monospace',
                display: 'flex',
                alignItems: 'center',
                gap: 1
              }}>
                <Storage sx={{ fontSize: 20 }} />
                SAVED SCANS ({savedScans.length})
              </Typography>
            </Box>
            
            <Box sx={{ maxHeight: 400, overflow: 'auto' }}>
              <Table size="small" sx={{ 
                '& .MuiTableCell-root': { 
                  borderColor: alpha(CYBER_COLORS.primary, 0.1),
                  color: CYBER_COLORS.text,
                  fontFamily: '"Share Tech Mono", monospace',
                  py: 1.5,
                }
              }}>
                <TableHead>
                  <TableRow sx={{ bgcolor: alpha(CYBER_COLORS.dark, 0.5) }}>
                    <TableCell sx={{ color: CYBER_COLORS.primary }}>NAME / ID</TableCell>
                    <TableCell sx={{ color: CYBER_COLORS.primary }}>TARGET</TableCell>
                    <TableCell sx={{ color: CYBER_COLORS.primary }}>STATUS</TableCell>
                    <TableCell sx={{ color: CYBER_COLORS.primary }} align="center">FINDINGS</TableCell>
                    <TableCell sx={{ color: CYBER_COLORS.primary }}>DATE</TableCell>
                    <TableCell sx={{ color: CYBER_COLORS.primary }} align="center">ACTIONS</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedScans.map((scan) => (
                    <TableRow 
                      key={scan.scan_id}
                      hover
                      onClick={() => handleLoadSavedScan(scan.scan_id)}
                      sx={{ 
                        cursor: 'pointer',
                        '&:hover': { 
                          bgcolor: alpha(CYBER_COLORS.primary, 0.1) 
                        }
                      }}
                    >
                      <TableCell>
                        <Box>
                          {scan.scan_name && (
                            <Typography sx={{ 
                              color: CYBER_COLORS.text, 
                              fontWeight: 600,
                              fontSize: '0.9rem'
                            }}>
                              {scan.scan_name}
                            </Typography>
                          )}
                          <Typography sx={{ 
                            color: CYBER_COLORS.textMuted, 
                            fontSize: '0.75rem',
                            fontFamily: '"Share Tech Mono", monospace'
                          }}>
                            {scan.scan_id}
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontSize: '0.85rem' }}>
                          {scan.target?.length > 30 ? `${scan.target.slice(0, 30)}...` : scan.target}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={scan.status?.toUpperCase()} 
                          size="small"
                          sx={{ 
                            bgcolor: scan.status === 'completed' 
                              ? alpha(CYBER_COLORS.success, 0.2) 
                              : scan.status === 'failed' 
                                ? alpha(CYBER_COLORS.danger, 0.2)
                                : alpha(CYBER_COLORS.warning, 0.2),
                            color: scan.status === 'completed' 
                              ? CYBER_COLORS.success 
                              : scan.status === 'failed' 
                                ? CYBER_COLORS.danger
                                : CYBER_COLORS.warning,
                            fontFamily: '"Share Tech Mono", monospace',
                            fontSize: '0.7rem'
                          }}
                        />
                      </TableCell>
                      <TableCell align="center">
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center' }}>
                          {scan.critical_count > 0 && (
                            <Chip 
                              label={scan.critical_count} 
                              size="small" 
                              sx={{ 
                                bgcolor: CYBER_COLORS.danger, 
                                color: 'white',
                                minWidth: 24,
                                height: 20,
                                '& .MuiChip-label': { px: 0.5, fontSize: '0.7rem' }
                              }} 
                            />
                          )}
                          {scan.high_count > 0 && (
                            <Chip 
                              label={scan.high_count} 
                              size="small" 
                              sx={{ 
                                bgcolor: CYBER_COLORS.warning, 
                                color: 'black',
                                minWidth: 24,
                                height: 20,
                                '& .MuiChip-label': { px: 0.5, fontSize: '0.7rem' }
                              }} 
                            />
                          )}
                          <Typography sx={{ color: CYBER_COLORS.textMuted, fontSize: '0.8rem', ml: 0.5 }}>
                            {scan.findings_count} total
                          </Typography>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Typography sx={{ fontSize: '0.8rem', color: CYBER_COLORS.textMuted }}>
                          {scan.started_at ? new Date(scan.started_at).toLocaleDateString() : 'N/A'}
                        </Typography>
                        <Typography sx={{ fontSize: '0.7rem', color: alpha(CYBER_COLORS.textMuted, 0.7) }}>
                          {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : ''}
                        </Typography>
                        {scan.duration_seconds && (
                          <Typography sx={{ fontSize: '0.7rem', color: alpha(CYBER_COLORS.textMuted, 0.6) }}>
                            {Math.round(scan.duration_seconds / 60)}min
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell align="center">
                        <Box sx={{ display: 'flex', gap: 0.5, justifyContent: 'center' }}>
                          <Tooltip title="Load Scan">
                            <IconButton 
                              size="small" 
                              onClick={(e) => {
                                e.stopPropagation();
                                handleLoadSavedScan(scan.scan_id);
                              }}
                              sx={{ color: CYBER_COLORS.primary }}
                            >
                              <Visibility fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Scan">
                            <IconButton 
                              size="small" 
                              onClick={(e) => handleDeleteScan(scan.scan_id, e)}
                              sx={{ 
                                color: CYBER_COLORS.danger,
                                '&:hover': { bgcolor: alpha(CYBER_COLORS.danger, 0.1) }
                              }}
                            >
                              <Delete fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          </CyberPaper>
        )}
      </Box>

      {/* AI Chat Widget */}
      <DynamicScanAIChatWidget
        scanResult={scanResult}
        scanId={scanId}
      />
    </Box>
  );
};

export default DynamicSecurityScannerPage;
