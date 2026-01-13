/**
 * Findings Dashboard Component
 * 
 * Burp Suite-inspired dashboard with:
 * - Statistics overview with charts
 * - Advanced filtering (severity, confidence, type, scanner)
 * - Bulk actions (mark FP, export, assign)
 * - Sortable and searchable table view
 * - Confidence level distribution
 */

import React, { useState, useMemo, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Card,
  CardContent,
  Chip,
  TextField,
  InputAdornment,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Button,
  ButtonGroup,
  IconButton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  TablePagination,
  Checkbox,
  alpha,
  useTheme,
  Collapse,
  Divider,
  LinearProgress,
  Badge,
  Stack,
  ToggleButtonGroup,
  ToggleButton,
} from '@mui/material';
import {
  Search as SearchIcon,
  FilterList as FilterIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  ViewList as ViewListIcon,
  ViewModule as ViewModuleIcon,
  ExpandMore as ExpandMoreIcon,
  ExpandLess as ExpandLessIcon,
  BugReport as BugReportIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Cancel as CancelIcon,
  Help as HelpIcon,
  ThumbDown as ThumbDownIcon,
  Flag as FlagIcon,
  TrendingUp as TrendingUpIcon,
  PieChart as PieChartIcon,
  Assessment as AssessmentIcon,
  Speed as SpeedIcon,
} from '@mui/icons-material';
import { EnhancedFindingCard, FindingData, ConfidenceLevel } from './EnhancedFindingCard';

interface FindingsDashboardProps {
  findings: FindingData[];
  onMarkFalsePositive?: (findingId: number, reason: string) => Promise<void>;
  onVerify?: (findingId: number) => Promise<void>;
  onBulkAction?: (action: string, findingIds: number[]) => Promise<void>;
  onExport?: (format: string, findings: FindingData[]) => void;
  onRefresh?: () => void;
  loading?: boolean;
  projectName?: string;
}

// Statistics Card Component
const StatCard: React.FC<{
  title: string;
  value: number | string;
  subtitle?: string;
  icon: React.ReactNode;
  color: string;
  trend?: number;
}> = ({ title, value, subtitle, icon, color, trend }) => {
  const theme = useTheme();
  
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
          <Box>
            <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', fontWeight: 600 }}>
              {title}
            </Typography>
            <Typography variant="h4" fontWeight="bold" sx={{ color, my: 0.5 }}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="caption" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </Box>
          <Box
            sx={{
              p: 1,
              borderRadius: 2,
              bgcolor: alpha(color, 0.1),
              color: color,
            }}
          >
            {icon}
          </Box>
        </Box>
        {trend !== undefined && (
          <Box sx={{ display: 'flex', alignItems: 'center', mt: 1, gap: 0.5 }}>
            <TrendingUpIcon fontSize="small" sx={{ color: trend >= 0 ? '#22c55e' : '#ef4444' }} />
            <Typography variant="caption" sx={{ color: trend >= 0 ? '#22c55e' : '#ef4444' }}>
              {trend >= 0 ? '+' : ''}{trend}% from last scan
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

// Confidence Distribution Bar
const ConfidenceDistribution: React.FC<{
  certain: number;
  firm: number;
  tentative: number;
  falsePositive: number;
}> = ({ certain, firm, tentative, falsePositive }) => {
  const total = certain + firm + tentative + falsePositive || 1;
  
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="subtitle2" gutterBottom>
        Confidence Distribution
      </Typography>
      <Box sx={{ display: 'flex', height: 24, borderRadius: 1, overflow: 'hidden', mb: 1 }}>
        {certain > 0 && (
          <Tooltip title={`Certain: ${certain} (${((certain/total)*100).toFixed(0)}%)`}>
            <Box sx={{ width: `${(certain/total)*100}%`, bgcolor: '#ef4444' }} />
          </Tooltip>
        )}
        {firm > 0 && (
          <Tooltip title={`Firm: ${firm} (${((firm/total)*100).toFixed(0)}%)`}>
            <Box sx={{ width: `${(firm/total)*100}%`, bgcolor: '#f97316' }} />
          </Tooltip>
        )}
        {tentative > 0 && (
          <Tooltip title={`Tentative: ${tentative} (${((tentative/total)*100).toFixed(0)}%)`}>
            <Box sx={{ width: `${(tentative/total)*100}%`, bgcolor: '#eab308' }} />
          </Tooltip>
        )}
        {falsePositive > 0 && (
          <Tooltip title={`False Positive: ${falsePositive} (${((falsePositive/total)*100).toFixed(0)}%)`}>
            <Box sx={{ width: `${(falsePositive/total)*100}%`, bgcolor: '#6b7280' }} />
          </Tooltip>
        )}
      </Box>
      <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <Box sx={{ width: 12, height: 12, borderRadius: 0.5, bgcolor: '#ef4444' }} />
          <Typography variant="caption">Certain ({certain})</Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <Box sx={{ width: 12, height: 12, borderRadius: 0.5, bgcolor: '#f97316' }} />
          <Typography variant="caption">Firm ({firm})</Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <Box sx={{ width: 12, height: 12, borderRadius: 0.5, bgcolor: '#eab308' }} />
          <Typography variant="caption">Tentative ({tentative})</Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
          <Box sx={{ width: 12, height: 12, borderRadius: 0.5, bgcolor: '#6b7280' }} />
          <Typography variant="caption">FP ({falsePositive})</Typography>
        </Box>
      </Box>
    </Box>
  );
};

export const FindingsDashboard: React.FC<FindingsDashboardProps> = ({
  findings,
  onMarkFalsePositive,
  onVerify,
  onBulkAction,
  onExport,
  onRefresh,
  loading = false,
  projectName,
}) => {
  const theme = useTheme();
  
  // State
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [confidenceFilter, setConfidenceFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [showFalsePositives, setShowFalsePositives] = useState(false);
  const [viewMode, setViewMode] = useState<'cards' | 'table'>('cards');
  const [filtersExpanded, setFiltersExpanded] = useState(true);
  const [selectedFindings, setSelectedFindings] = useState<Set<number>>(new Set());
  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'date'>('severity');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  // Calculate statistics
  const stats = useMemo(() => {
    const total = findings.length;
    const critical = findings.filter(f => f.severity === 'critical' && !f.is_false_positive).length;
    const high = findings.filter(f => f.severity === 'high' && !f.is_false_positive).length;
    const medium = findings.filter(f => f.severity === 'medium' && !f.is_false_positive).length;
    const low = findings.filter(f => f.severity === 'low' && !f.is_false_positive).length;
    const fps = findings.filter(f => f.is_false_positive).length;
    
    const certain = findings.filter(f => f.confidence_level === 'certain' || (f.confidence && f.confidence >= 0.95)).length;
    const firm = findings.filter(f => f.confidence_level === 'firm' || (f.confidence && f.confidence >= 0.75 && f.confidence < 0.95)).length;
    const tentative = findings.filter(f => f.confidence_level === 'tentative' || (f.confidence && f.confidence >= 0.50 && f.confidence < 0.75)).length;
    
    const types = new Set(findings.map(f => f.type));
    const avgConfidence = findings.length > 0
      ? findings.reduce((sum, f) => sum + (f.confidence || 0.5), 0) / findings.length
      : 0;

    return {
      total,
      critical,
      high,
      medium,
      low,
      falsePositives: fps,
      certain,
      firm,
      tentative,
      uniqueTypes: types.size,
      avgConfidence,
      activeFindings: total - fps,
    };
  }, [findings]);

  // Get unique types for filter dropdown
  const uniqueTypes = useMemo(() => {
    return Array.from(new Set(findings.map(f => f.type))).sort();
  }, [findings]);

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let result = [...findings];

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(f =>
        f.title.toLowerCase().includes(query) ||
        f.summary.toLowerCase().includes(query) ||
        f.file_path?.toLowerCase().includes(query) ||
        f.type.toLowerCase().includes(query)
      );
    }

    // Severity filter
    if (severityFilter !== 'all') {
      result = result.filter(f => f.severity === severityFilter);
    }

    // Confidence filter
    if (confidenceFilter !== 'all') {
      result = result.filter(f => {
        const level = f.confidence_level || 
          (f.confidence && f.confidence >= 0.95 ? 'certain' :
           f.confidence && f.confidence >= 0.75 ? 'firm' : 'tentative');
        return level === confidenceFilter;
      });
    }

    // Type filter
    if (typeFilter !== 'all') {
      result = result.filter(f => f.type === typeFilter);
    }

    // False positive filter
    if (!showFalsePositives) {
      result = result.filter(f => !f.is_false_positive);
    }

    // Sort
    result.sort((a, b) => {
      let comparison = 0;
      
      if (sortBy === 'severity') {
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        comparison = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      } else if (sortBy === 'confidence') {
        comparison = (b.confidence || 0) - (a.confidence || 0);
      } else if (sortBy === 'date') {
        comparison = new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
      }
      
      return sortOrder === 'desc' ? comparison : -comparison;
    });

    return result;
  }, [findings, searchQuery, severityFilter, confidenceFilter, typeFilter, showFalsePositives, sortBy, sortOrder]);

  // Pagination
  const paginatedFindings = useMemo(() => {
    const start = page * rowsPerPage;
    return filteredFindings.slice(start, start + rowsPerPage);
  }, [filteredFindings, page, rowsPerPage]);

  // Selection handlers
  const handleSelectAll = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.checked) {
      setSelectedFindings(new Set(filteredFindings.map(f => f.id)));
    } else {
      setSelectedFindings(new Set());
    }
  }, [filteredFindings]);

  const handleSelectFinding = useCallback((id: number) => {
    setSelectedFindings(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  }, []);

  // Bulk action handler
  const handleBulkAction = useCallback(async (action: string) => {
    if (onBulkAction && selectedFindings.size > 0) {
      await onBulkAction(action, Array.from(selectedFindings));
      setSelectedFindings(new Set());
    }
  }, [onBulkAction, selectedFindings]);

  // Export handler
  const handleExport = useCallback((format: string) => {
    if (onExport) {
      const toExport = selectedFindings.size > 0
        ? filteredFindings.filter(f => selectedFindings.has(f.id))
        : filteredFindings;
      onExport(format, toExport);
    }
  }, [onExport, filteredFindings, selectedFindings]);

  return (
    <Box>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 3 }}>
        <Box>
          <Typography variant="h5" fontWeight="bold">
            Security Findings
          </Typography>
          {projectName && (
            <Typography variant="body2" color="text.secondary">
              {projectName} • {stats.activeFindings} active findings
            </Typography>
          )}
        </Box>
        <Box sx={{ display: 'flex', gap: 1 }}>
          {onRefresh && (
            <Button
              startIcon={<RefreshIcon />}
              onClick={onRefresh}
              disabled={loading}
            >
              Refresh
            </Button>
          )}
          {onExport && (
            <ButtonGroup variant="outlined" size="small">
              <Button startIcon={<DownloadIcon />} onClick={() => handleExport('json')}>
                JSON
              </Button>
              <Button onClick={() => handleExport('csv')}>CSV</Button>
              <Button onClick={() => handleExport('pdf')}>PDF</Button>
            </ButtonGroup>
          )}
        </Box>
      </Box>

      {loading && <LinearProgress sx={{ mb: 2 }} />}

      {/* Statistics Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Total Findings"
            value={stats.total}
            subtitle={`${stats.activeFindings} active`}
            icon={<BugReportIcon />}
            color={theme.palette.primary.main}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Critical"
            value={stats.critical}
            icon={<ErrorIcon />}
            color="#dc2626"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="High"
            value={stats.high}
            icon={<WarningIcon />}
            color="#ea580c"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="Avg Confidence"
            value={`${(stats.avgConfidence * 100).toFixed(0)}%`}
            icon={<SpeedIcon />}
            color="#2563eb"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={2.4}>
          <StatCard
            title="False Positives"
            value={stats.falsePositives}
            subtitle={`${((stats.falsePositives / stats.total) * 100).toFixed(1)}% rate`}
            icon={<CancelIcon />}
            color="#6b7280"
          />
        </Grid>
      </Grid>

      {/* Confidence Distribution */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <ConfidenceDistribution
          certain={stats.certain}
          firm={stats.firm}
          tentative={stats.tentative}
          falsePositive={stats.falsePositives}
        />
      </Paper>

      {/* Filters */}
      <Paper sx={{ p: 2, mb: 3 }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            cursor: 'pointer',
          }}
          onClick={() => setFiltersExpanded(!filtersExpanded)}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <FilterIcon />
            <Typography variant="subtitle1" fontWeight={600}>
              Filters
            </Typography>
            {(severityFilter !== 'all' || confidenceFilter !== 'all' || typeFilter !== 'all' || searchQuery) && (
              <Chip size="small" label="Active" color="primary" />
            )}
          </Box>
          {filtersExpanded ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </Box>
        
        <Collapse in={filtersExpanded}>
          <Box sx={{ mt: 2 }}>
            <Grid container spacing={2} alignItems="center">
              {/* Search */}
              <Grid item xs={12} md={3}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Search findings..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon fontSize="small" />
                      </InputAdornment>
                    ),
                  }}
                />
              </Grid>

              {/* Severity Filter */}
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Severity</InputLabel>
                  <Select
                    value={severityFilter}
                    label="Severity"
                    onChange={(e) => setSeverityFilter(e.target.value)}
                  >
                    <MenuItem value="all">All Severities</MenuItem>
                    <MenuItem value="critical">Critical</MenuItem>
                    <MenuItem value="high">High</MenuItem>
                    <MenuItem value="medium">Medium</MenuItem>
                    <MenuItem value="low">Low</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Confidence Filter */}
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Confidence</InputLabel>
                  <Select
                    value={confidenceFilter}
                    label="Confidence"
                    onChange={(e) => setConfidenceFilter(e.target.value)}
                  >
                    <MenuItem value="all">All Levels</MenuItem>
                    <MenuItem value="certain">Certain (95%+)</MenuItem>
                    <MenuItem value="firm">Firm (75-94%)</MenuItem>
                    <MenuItem value="tentative">Tentative (50-74%)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* Type Filter */}
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Type</InputLabel>
                  <Select
                    value={typeFilter}
                    label="Type"
                    onChange={(e) => setTypeFilter(e.target.value)}
                  >
                    <MenuItem value="all">All Types</MenuItem>
                    {uniqueTypes.map(type => (
                      <MenuItem key={type} value={type}>{type}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Grid>

              {/* Sort */}
              <Grid item xs={6} md={2}>
                <FormControl fullWidth size="small">
                  <InputLabel>Sort By</InputLabel>
                  <Select
                    value={sortBy}
                    label="Sort By"
                    onChange={(e) => setSortBy(e.target.value as any)}
                  >
                    <MenuItem value="severity">Severity</MenuItem>
                    <MenuItem value="confidence">Confidence</MenuItem>
                    <MenuItem value="date">Date</MenuItem>
                  </Select>
                </FormControl>
              </Grid>

              {/* View Mode & Options */}
              <Grid item xs={12} md={1}>
                <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                  <ToggleButtonGroup
                    value={viewMode}
                    exclusive
                    onChange={(_, value) => value && setViewMode(value)}
                    size="small"
                  >
                    <ToggleButton value="cards">
                      <ViewModuleIcon fontSize="small" />
                    </ToggleButton>
                    <ToggleButton value="table">
                      <ViewListIcon fontSize="small" />
                    </ToggleButton>
                  </ToggleButtonGroup>
                </Box>
              </Grid>
            </Grid>

            {/* Additional Options */}
            <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 2 }}>
              <Chip
                label={showFalsePositives ? "Hiding False Positives" : "Show False Positives"}
                onClick={() => setShowFalsePositives(!showFalsePositives)}
                color={showFalsePositives ? "default" : "primary"}
                variant={showFalsePositives ? "filled" : "outlined"}
                deleteIcon={showFalsePositives ? <CheckCircleIcon /> : undefined}
              />
              
              <Typography variant="body2" color="text.secondary">
                Showing {filteredFindings.length} of {findings.length} findings
              </Typography>
            </Box>
          </Box>
        </Collapse>
      </Paper>

      {/* Bulk Actions */}
      {selectedFindings.size > 0 && (
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Typography variant="body2" fontWeight={600}>
              {selectedFindings.size} selected
            </Typography>
            <Divider orientation="vertical" flexItem />
            {onBulkAction && (
              <>
                <Button
                  size="small"
                  startIcon={<ThumbDownIcon />}
                  onClick={() => handleBulkAction('mark_false_positive')}
                >
                  Mark as False Positive
                </Button>
                <Button
                  size="small"
                  startIcon={<FlagIcon />}
                  onClick={() => handleBulkAction('escalate')}
                >
                  Escalate
                </Button>
              </>
            )}
            <Button
              size="small"
              onClick={() => setSelectedFindings(new Set())}
            >
              Clear Selection
            </Button>
          </Box>
        </Paper>
      )}

      {/* Findings List */}
      {viewMode === 'cards' ? (
        <Box>
          {paginatedFindings.map(finding => (
            <Box key={finding.id} sx={{ display: 'flex', alignItems: 'flex-start', gap: 1 }}>
              <Checkbox
                checked={selectedFindings.has(finding.id)}
                onChange={() => handleSelectFinding(finding.id)}
                sx={{ mt: 1 }}
              />
              <Box sx={{ flexGrow: 1 }}>
                <EnhancedFindingCard
                  finding={finding}
                  onMarkFalsePositive={onMarkFalsePositive}
                  onVerify={onVerify}
                />
              </Box>
            </Box>
          ))}
        </Box>
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox">
                  <Checkbox
                    indeterminate={selectedFindings.size > 0 && selectedFindings.size < filteredFindings.length}
                    checked={selectedFindings.size === filteredFindings.length && filteredFindings.length > 0}
                    onChange={handleSelectAll}
                  />
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'severity'}
                    direction={sortOrder}
                    onClick={() => {
                      if (sortBy === 'severity') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortBy('severity');
                        setSortOrder('desc');
                      }
                    }}
                  >
                    Severity
                  </TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel
                    active={sortBy === 'confidence'}
                    direction={sortOrder}
                    onClick={() => {
                      if (sortBy === 'confidence') {
                        setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
                      } else {
                        setSortBy('confidence');
                        setSortOrder('desc');
                      }
                    }}
                  >
                    Confidence
                  </TableSortLabel>
                </TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Location</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {paginatedFindings.map(finding => (
                <TableRow
                  key={finding.id}
                  hover
                  selected={selectedFindings.has(finding.id)}
                  sx={{ opacity: finding.is_false_positive ? 0.5 : 1 }}
                >
                  <TableCell padding="checkbox">
                    <Checkbox
                      checked={selectedFindings.has(finding.id)}
                      onChange={() => handleSelectFinding(finding.id)}
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      size="small"
                      label={finding.severity}
                      sx={{
                        bgcolor: {
                          critical: '#fef2f2',
                          high: '#fff7ed',
                          medium: '#fefce8',
                          low: '#eff6ff',
                          info: '#f9fafb',
                        }[finding.severity],
                        color: {
                          critical: '#dc2626',
                          high: '#ea580c',
                          medium: '#ca8a04',
                          low: '#2563eb',
                          info: '#6b7280',
                        }[finding.severity],
                        fontWeight: 600,
                        fontSize: '0.7rem',
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      <LinearProgress
                        variant="determinate"
                        value={(finding.confidence || 0.5) * 100}
                        sx={{
                          width: 50,
                          height: 6,
                          borderRadius: 3,
                          bgcolor: alpha('#000', 0.1),
                        }}
                      />
                      <Typography variant="caption">
                        {((finding.confidence || 0.5) * 100).toFixed(0)}%
                      </Typography>
                    </Box>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
                      {finding.type}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {finding.is_false_positive && <s>{finding.title}</s>}
                      {!finding.is_false_positive && finding.title}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="caption" sx={{ fontFamily: 'monospace' }}>
                      {finding.file_path && `${finding.file_path.split('/').pop()}:${finding.start_line}`}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5}>
                      {onVerify && (
                        <Tooltip title="Verify">
                          <IconButton size="small" onClick={() => onVerify(finding.id)}>
                            <RefreshIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {onMarkFalsePositive && !finding.is_false_positive && (
                        <Tooltip title="Mark False Positive">
                          <IconButton size="small" onClick={() => onMarkFalsePositive(finding.id, 'Marked from table')}>
                            <ThumbDownIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50, 100]}
            component="div"
            count={filteredFindings.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={(_, newPage) => setPage(newPage)}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
          />
        </TableContainer>
      )}

      {/* Pagination for card view */}
      {viewMode === 'cards' && (
        <Box sx={{ display: 'flex', justifyContent: 'center', mt: 2 }}>
          <TablePagination
            rowsPerPageOptions={[10, 25, 50]}
            component="div"
            count={filteredFindings.length}
            rowsPerPage={rowsPerPage}
            page={page}
            onPageChange={(_, newPage) => setPage(newPage)}
            onRowsPerPageChange={(e) => {
              setRowsPerPage(parseInt(e.target.value, 10));
              setPage(0);
            }}
          />
        </Box>
      )}

      {/* Empty State */}
      {filteredFindings.length === 0 && !loading && (
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <SecurityIcon sx={{ fontSize: 64, color: 'text.disabled', mb: 2 }} />
          <Typography variant="h6" color="text.secondary">
            No findings match your filters
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Try adjusting your search or filter criteria
          </Typography>
        </Paper>
      )}
    </Box>
  );
};

export default FindingsDashboard;
