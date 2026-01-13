/**
 * Enhanced Finding Card Component
 * 
 * Burp Suite-inspired design with:
 * - Confidence level badges (Certain/Firm/Tentative/FP)
 * - False positive marking with feedback
 * - Expandable evidence and validation details
 * - Quick actions (verify, mark FP, escalate)
 * - Remediation code display
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Chip,
  IconButton,
  Collapse,
  Button,
  TextField,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Tooltip,
  LinearProgress,
  Divider,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  alpha,
  useTheme,
  Badge,
  Menu,
  MenuItem,
  Stack,
  Alert,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  Help as HelpIcon,
  Flag as FlagIcon,
  BugReport as BugReportIcon,
  Code as CodeIcon,
  Security as SecurityIcon,
  Verified as VerifiedIcon,
  ThumbDown as ThumbDownIcon,
  ThumbUp as ThumbUpIcon,
  MoreVert as MoreVertIcon,
  ContentCopy as ContentCopyIcon,
  OpenInNew as OpenInNewIcon,
  Refresh as RefreshIcon,
  Verified as VerifiedIcon2,
  PlayArrow as PlayArrowIcon,
  Description as DescriptionIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';

// Types
export type ConfidenceLevel = 'certain' | 'firm' | 'tentative' | 'false_positive';

export interface ValidationMethod {
  method: string;
  passed: boolean;
  confidence_delta: number;
  evidence: string;
}

export interface FindingData {
  id: number;
  title: string;
  summary: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file_path?: string;
  start_line?: number;
  end_line?: number;
  confidence?: number;
  confidence_level?: ConfidenceLevel;
  is_false_positive?: boolean;
  payload?: string;
  evidence?: string[];
  cwe_id?: string;
  cvss_score?: number;
  cvss_vector?: string;
  recommendation?: string;
  remediation_code?: string;
  validation_results?: ValidationMethod[];
  details?: {
    code_snippet?: string;
    data_flow?: string;
    scanner_detections?: Array<{
      scanner: string;
      rule_id?: string;
      message: string;
    }>;
    detected_by_scanners?: number;
    proof_of_concept?: string;
    request?: string;
    response?: string;
  };
  created_at?: string;
  marked_false_positive_at?: string;
  marked_false_positive_reason?: string;
}

interface EnhancedFindingCardProps {
  finding: FindingData;
  onMarkFalsePositive?: (findingId: number, reason: string) => Promise<void>;
  onVerify?: (findingId: number) => Promise<void>;
  onEscalate?: (findingId: number) => void;
  expanded?: boolean;
  showValidationDetails?: boolean;
}

// Confidence level styling
const confidenceConfig: Record<ConfidenceLevel, {
  label: string;
  color: string;
  bgColor: string;
  icon: React.ReactNode;
  description: string;
}> = {
  certain: {
    label: 'Certain',
    color: '#ef4444',
    bgColor: '#fef2f2',
    icon: <ErrorIcon />,
    description: 'Verified exploitation - no doubt',
  },
  firm: {
    label: 'Firm',
    color: '#f97316',
    bgColor: '#fff7ed',
    icon: <WarningIcon />,
    description: 'Strong evidence - high confidence',
  },
  tentative: {
    label: 'Tentative',
    color: '#eab308',
    bgColor: '#fefce8',
    icon: <HelpIcon />,
    description: 'Possible vulnerability - needs review',
  },
  false_positive: {
    label: 'False Positive',
    color: '#6b7280',
    bgColor: '#f3f4f6',
    icon: <CancelIcon />,
    description: 'Verified as not exploitable',
  },
};

// Severity styling
const severityConfig = {
  critical: { color: '#dc2626', bgColor: '#fef2f2', label: 'Critical' },
  high: { color: '#ea580c', bgColor: '#fff7ed', label: 'High' },
  medium: { color: '#ca8a04', bgColor: '#fefce8', label: 'Medium' },
  low: { color: '#2563eb', bgColor: '#eff6ff', label: 'Low' },
  info: { color: '#6b7280', bgColor: '#f9fafb', label: 'Info' },
};

export const EnhancedFindingCard: React.FC<EnhancedFindingCardProps> = ({
  finding,
  onMarkFalsePositive,
  onVerify,
  onEscalate,
  expanded: initialExpanded = false,
  showValidationDetails = true,
}) => {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(initialExpanded);
  const [fpDialogOpen, setFpDialogOpen] = useState(false);
  const [fpReason, setFpReason] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [menuAnchor, setMenuAnchor] = useState<null | HTMLElement>(null);

  const confidence = finding.confidence_level || 
    (finding.confidence && finding.confidence >= 0.95 ? 'certain' :
     finding.confidence && finding.confidence >= 0.75 ? 'firm' :
     finding.confidence && finding.confidence >= 0.50 ? 'tentative' : 'tentative');
  
  const confidenceStyle = confidenceConfig[confidence];
  const severityStyle = severityConfig[finding.severity] || severityConfig.medium;

  const handleMarkFalsePositive = useCallback(async () => {
    if (onMarkFalsePositive && fpReason.trim()) {
      await onMarkFalsePositive(finding.id, fpReason);
      setFpDialogOpen(false);
      setFpReason('');
    }
  }, [finding.id, fpReason, onMarkFalsePositive]);

  const handleVerify = useCallback(async () => {
    if (onVerify) {
      setVerifying(true);
      try {
        await onVerify(finding.id);
      } finally {
        setVerifying(false);
      }
    }
  }, [finding.id, onVerify]);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <>
      <Card
        sx={{
          mb: 2,
          border: `1px solid ${alpha(severityStyle.color, 0.3)}`,
          borderLeft: `4px solid ${severityStyle.color}`,
          bgcolor: finding.is_false_positive ? alpha('#6b7280', 0.05) : 'background.paper',
          opacity: finding.is_false_positive ? 0.7 : 1,
          transition: 'all 0.2s ease',
          '&:hover': {
            boxShadow: theme.shadows[4],
          },
        }}
      >
        <CardContent sx={{ pb: 1 }}>
          {/* Header Row */}
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, mb: 1 }}>
            {/* Severity Badge */}
            <Chip
              size="small"
              label={severityStyle.label}
              sx={{
                bgcolor: severityStyle.bgColor,
                color: severityStyle.color,
                fontWeight: 600,
                fontSize: '0.7rem',
              }}
            />
            
            {/* Confidence Badge */}
            <Tooltip title={confidenceStyle.description}>
              <Chip
                size="small"
                icon={<Box sx={{ color: confidenceStyle.color, display: 'flex' }}>{confidenceStyle.icon}</Box>}
                label={confidenceStyle.label}
                sx={{
                  bgcolor: confidenceStyle.bgColor,
                  color: confidenceStyle.color,
                  fontWeight: 600,
                  fontSize: '0.7rem',
                  '& .MuiChip-icon': { color: confidenceStyle.color },
                }}
              />
            </Tooltip>

            {/* CVSS Score */}
            {finding.cvss_score && (
              <Chip
                size="small"
                label={`CVSS: ${finding.cvss_score.toFixed(1)}`}
                sx={{
                  bgcolor: alpha(theme.palette.info.main, 0.1),
                  color: theme.palette.info.main,
                  fontSize: '0.7rem',
                }}
              />
            )}

            {/* Scanner count badge */}
            {finding.details?.detected_by_scanners && finding.details.detected_by_scanners > 1 && (
              <Tooltip title={`Detected by ${finding.details.detected_by_scanners} scanners`}>
                <Chip
                  size="small"
                  icon={<VerifiedIcon2 fontSize="small" />}
                  label={`${finding.details.detected_by_scanners} scanners`}
                  color="success"
                  variant="outlined"
                  sx={{ fontSize: '0.7rem' }}
                />
              </Tooltip>
            )}

            {/* CWE Badge */}
            {finding.cwe_id && (
              <Chip
                size="small"
                label={finding.cwe_id}
                variant="outlined"
                sx={{ fontSize: '0.7rem' }}
                onClick={() => window.open(`https://cwe.mitre.org/data/definitions/${(finding.cwe_id || '').replace('CWE-', '')}.html`, '_blank')}
              />
            )}

            <Box sx={{ flexGrow: 1 }} />

            {/* Actions Menu */}
            <IconButton size="small" onClick={(e) => setMenuAnchor(e.currentTarget)}>
              <MoreVertIcon fontSize="small" />
            </IconButton>
            <Menu
              anchorEl={menuAnchor}
              open={Boolean(menuAnchor)}
              onClose={() => setMenuAnchor(null)}
            >
              {onVerify && (
                <MenuItem onClick={() => { setMenuAnchor(null); handleVerify(); }}>
                  <ListItemIcon><RefreshIcon fontSize="small" /></ListItemIcon>
                  Re-verify Finding
                </MenuItem>
              )}
              {onMarkFalsePositive && !finding.is_false_positive && (
                <MenuItem onClick={() => { setMenuAnchor(null); setFpDialogOpen(true); }}>
                  <ListItemIcon><ThumbDownIcon fontSize="small" /></ListItemIcon>
                  Mark as False Positive
                </MenuItem>
              )}
              {onEscalate && (
                <MenuItem onClick={() => { setMenuAnchor(null); onEscalate(finding.id); }}>
                  <ListItemIcon><FlagIcon fontSize="small" /></ListItemIcon>
                  Escalate
                </MenuItem>
              )}
              <MenuItem onClick={() => { copyToClipboard(JSON.stringify(finding, null, 2)); setMenuAnchor(null); }}>
                <ListItemIcon><ContentCopyIcon fontSize="small" /></ListItemIcon>
                Copy JSON
              </MenuItem>
            </Menu>
          </Box>

          {/* Title */}
          <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 0.5 }}>
            {finding.is_false_positive && (
              <Box component="span" sx={{ textDecoration: 'line-through', opacity: 0.6 }}>
                {finding.title}
              </Box>
            )}
            {!finding.is_false_positive && finding.title}
          </Typography>

          {/* Summary */}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            {finding.summary}
          </Typography>

          {/* Location */}
          {finding.file_path && (
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mb: 1 }}>
              <DescriptionIcon fontSize="small" sx={{ color: 'text.secondary' }} />
              <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                {finding.file_path}
                {finding.start_line && `:${finding.start_line}`}
                {finding.end_line && finding.end_line !== finding.start_line && `-${finding.end_line}`}
              </Typography>
              <IconButton size="small" onClick={() => copyToClipboard(finding.file_path || '')}>
                <ContentCopyIcon fontSize="inherit" />
              </IconButton>
            </Box>
          )}

          {/* Confidence Progress Bar */}
          {finding.confidence !== undefined && (
            <Box sx={{ mb: 1 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  Confidence
                </Typography>
                <Typography variant="caption" fontWeight={600}>
                  {(finding.confidence * 100).toFixed(0)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={finding.confidence * 100}
                sx={{
                  height: 6,
                  borderRadius: 3,
                  bgcolor: alpha(confidenceStyle.color, 0.1),
                  '& .MuiLinearProgress-bar': {
                    bgcolor: confidenceStyle.color,
                    borderRadius: 3,
                  },
                }}
              />
            </Box>
          )}

          {/* Quick Action Buttons */}
          <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
            <Button
              size="small"
              startIcon={expanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? 'Hide Details' : 'Show Details'}
            </Button>
            
            {verifying ? (
              <Button size="small" disabled startIcon={<RefreshIcon className="spin" />}>
                Verifying...
              </Button>
            ) : onVerify && (
              <Button size="small" startIcon={<PlayArrowIcon />} onClick={handleVerify} color="primary">
                Verify
              </Button>
            )}
            
            {!finding.is_false_positive && onMarkFalsePositive && (
              <Button
                size="small"
                startIcon={<ThumbDownIcon />}
                onClick={() => setFpDialogOpen(true)}
                color="inherit"
              >
                False Positive
              </Button>
            )}
          </Box>

          {/* Expanded Details */}
          <Collapse in={expanded}>
            <Box sx={{ mt: 2 }}>
              <Divider sx={{ mb: 2 }} />

              {/* Validation Results */}
              {showValidationDetails && finding.validation_results && finding.validation_results.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Validation Results
                  </Typography>
                  <List dense>
                    {finding.validation_results.map((result, idx) => (
                      <ListItem key={idx} sx={{ py: 0.5 }}>
                        <ListItemIcon sx={{ minWidth: 32 }}>
                          {result.passed ? (
                            <CheckCircleIcon fontSize="small" color="success" />
                          ) : (
                            <CancelIcon fontSize="small" color="error" />
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography variant="body2">
                              <strong>{result.method}</strong>: {result.evidence}
                            </Typography>
                          }
                          secondary={`Confidence ${result.confidence_delta >= 0 ? '+' : ''}${(result.confidence_delta * 100).toFixed(0)}%`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Box>
              )}

              {/* Code Snippet */}
              {finding.details?.code_snippet && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Code Snippet
                  </Typography>
                  <Box
                    sx={{
                      bgcolor: alpha('#000', 0.03),
                      p: 1.5,
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      overflow: 'auto',
                      maxHeight: 200,
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {finding.details.code_snippet}
                  </Box>
                </Box>
              )}

              {/* Data Flow */}
              {finding.details?.data_flow && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <TimelineIcon fontSize="small" /> Data Flow
                  </Typography>
                  <Alert severity="info" sx={{ fontSize: '0.85rem' }}>
                    {finding.details.data_flow}
                  </Alert>
                </Box>
              )}

              {/* Payload */}
              {finding.payload && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Payload
                  </Typography>
                  <Box
                    sx={{
                      bgcolor: alpha('#ef4444', 0.05),
                      border: `1px solid ${alpha('#ef4444', 0.2)}`,
                      p: 1.5,
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                    }}
                  >
                    <Box sx={{ flexGrow: 1, overflow: 'auto' }}>{finding.payload}</Box>
                    <IconButton size="small" onClick={() => copyToClipboard(finding.payload || '')}>
                      <ContentCopyIcon fontSize="small" />
                    </IconButton>
                  </Box>
                </Box>
              )}

              {/* Proof of Concept */}
              {finding.details?.proof_of_concept && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Proof of Concept
                  </Typography>
                  <Box
                    sx={{
                      bgcolor: alpha('#000', 0.03),
                      p: 1.5,
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.75rem',
                      overflow: 'auto',
                      maxHeight: 300,
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {finding.details.proof_of_concept}
                  </Box>
                </Box>
              )}

              {/* Scanner Detections */}
              {finding.details?.scanner_detections && finding.details.scanner_detections.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Scanner Detections
                  </Typography>
                  <Stack spacing={1}>
                    {finding.details.scanner_detections.map((detection, idx) => (
                      <Box
                        key={idx}
                        sx={{
                          p: 1,
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                          borderRadius: 1,
                          border: `1px solid ${alpha(theme.palette.primary.main, 0.1)}`,
                        }}
                      >
                        <Typography variant="body2" fontWeight={600}>
                          {detection.scanner}
                          {detection.rule_id && (
                            <Chip
                              size="small"
                              label={detection.rule_id}
                              sx={{ ml: 1, height: 20, fontSize: '0.7rem' }}
                            />
                          )}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {detection.message}
                        </Typography>
                      </Box>
                    ))}
                  </Stack>
                </Box>
              )}

              {/* Recommendation */}
              {finding.recommendation && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Recommendation
                  </Typography>
                  <Alert severity="warning" icon={<SecurityIcon />}>
                    {finding.recommendation}
                  </Alert>
                </Box>
              )}

              {/* Remediation Code */}
              {finding.remediation_code && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                    <CodeIcon fontSize="small" /> Remediation Code
                  </Typography>
                  <Box
                    sx={{
                      bgcolor: alpha('#22c55e', 0.05),
                      border: `1px solid ${alpha('#22c55e', 0.2)}`,
                      p: 1.5,
                      borderRadius: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.8rem',
                      overflow: 'auto',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {finding.remediation_code}
                  </Box>
                </Box>
              )}

              {/* CVSS Vector */}
              {finding.cvss_vector && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    CVSS Vector
                  </Typography>
                  <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                    {finding.cvss_vector}
                  </Typography>
                </Box>
              )}
            </Box>
          </Collapse>
        </CardContent>
      </Card>

      {/* False Positive Dialog */}
      <Dialog open={fpDialogOpen} onClose={() => setFpDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Mark as False Positive</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Provide a reason for marking this finding as a false positive. This feedback helps improve detection accuracy.
          </Typography>
          <TextField
            fullWidth
            multiline
            rows={3}
            label="Reason"
            placeholder="e.g., This is test code, sanitization is applied elsewhere, etc."
            value={fpReason}
            onChange={(e) => setFpReason(e.target.value)}
          />
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
            Your feedback will be used to train the false positive detection system.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setFpDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={handleMarkFalsePositive}
            variant="contained"
            disabled={!fpReason.trim()}
            startIcon={<ThumbDownIcon />}
          >
            Mark as False Positive
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

// Add a keyframe animation for the spinner
const styles = `
@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}
.spin {
  animation: spin 1s linear infinite;
}
`;

// Inject styles
if (typeof document !== 'undefined') {
  const styleElement = document.createElement('style');
  styleElement.textContent = styles;
  document.head.appendChild(styleElement);
}

export default EnhancedFindingCard;
