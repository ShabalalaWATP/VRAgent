import React, { useState, useMemo } from "react";
import {
  Box,
  Typography,
  TextField,
  InputAdornment,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TableSortLabel,
  Paper,
  Collapse,
  IconButton,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tooltip,
  alpha,
  useTheme,
} from "@mui/material";
import {
  Search as SearchIcon,
  KeyboardArrowDown as ExpandIcon,
  KeyboardArrowUp as CollapseIcon,
  FilterList as FilterIcon,
  Error as CriticalIcon,
  Warning as HighIcon,
  ReportProblem as MediumIcon,
  Info as LowIcon,
  CheckCircle as InfoIcon,
  OpenInNew as OpenInNewIcon,
} from "@mui/icons-material";

interface NmapFinding {
  category: string;
  severity: string;
  title: string;
  description: string;
  host?: string;
  port?: number;
  service?: string;
  evidence?: string;
  cve_ids?: string[];
  recommendation?: string;
}

interface NmapFindingsTabProps {
  findings: NmapFinding[];
  onHostClick?: (host: string) => void;
}

type SortField = "severity" | "host" | "port" | "category" | "title";
type SortOrder = "asc" | "desc";

const severityOrder = ["critical", "high", "medium", "low", "info"];

const getSeverityColor = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical": return "error";
    case "high": return "error";
    case "medium": return "warning";
    case "low": return "info";
    default: return "default";
  }
};

const getSeverityIcon = (severity: string) => {
  switch (severity?.toLowerCase()) {
    case "critical": return <CriticalIcon fontSize="small" color="error" />;
    case "high": return <HighIcon fontSize="small" color="error" />;
    case "medium": return <MediumIcon fontSize="small" color="warning" />;
    case "low": return <LowIcon fontSize="small" color="info" />;
    default: return <InfoIcon fontSize="small" color="success" />;
  }
};

const FindingRow: React.FC<{
  finding: NmapFinding;
  onHostClick?: (host: string) => void;
}> = ({ finding, onHostClick }) => {
  const [expanded, setExpanded] = useState(false);
  const theme = useTheme();

  return (
    <>
      <TableRow
        hover
        sx={{
          cursor: "pointer",
          bgcolor: expanded
            ? alpha(
                finding.severity === "critical" || finding.severity === "high"
                  ? theme.palette.error.main
                  : finding.severity === "medium"
                  ? theme.palette.warning.main
                  : theme.palette.info.main,
                0.08
              )
            : "inherit",
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <TableCell padding="checkbox">
          <IconButton size="small">
            {expanded ? <CollapseIcon /> : <ExpandIcon />}
          </IconButton>
        </TableCell>
        <TableCell>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            {getSeverityIcon(finding.severity)}
            <Chip
              label={finding.severity.toUpperCase()}
              size="small"
              color={getSeverityColor(finding.severity) as any}
              sx={{ minWidth: 80 }}
            />
          </Box>
        </TableCell>
        <TableCell>
          <Tooltip title="Click to view host details">
            <Chip
              label={finding.host || "N/A"}
              size="small"
              variant="outlined"
              onClick={(e) => {
                e.stopPropagation();
                if (finding.host) {
                  onHostClick?.(finding.host);
                }
              }}
              sx={{ fontFamily: "monospace", cursor: finding.host ? "pointer" : "default" }}
            />
          </Tooltip>
        </TableCell>
        <TableCell>
          {finding.port ? (
            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
              {finding.port}
            </Typography>
          ) : (
            "-"
          )}
        </TableCell>
        <TableCell>
          <Chip label={finding.category} size="small" variant="outlined" />
        </TableCell>
        <TableCell>
          <Typography variant="body2" sx={{ fontWeight: 500 }}>
            {finding.title}
          </Typography>
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={6} sx={{ p: 0, borderBottom: expanded ? undefined : "none" }}>
          <Collapse in={expanded} timeout="auto" unmountOnExit>
            <Box
              sx={{
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Description
              </Typography>
              <Typography variant="body2" sx={{ mb: 2 }}>
                {finding.description}
              </Typography>

              {finding.service && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Service
                  </Typography>
                  <Chip label={finding.service} size="small" />
                </Box>
              )}

              {finding.evidence && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Evidence
                  </Typography>
                  <Paper
                    sx={{
                      p: 1.5,
                      bgcolor: alpha(theme.palette.background.paper, 0.8),
                      fontFamily: "monospace",
                      fontSize: "0.8rem",
                      whiteSpace: "pre-wrap",
                      overflow: "auto",
                      maxHeight: 200,
                    }}
                  >
                    {finding.evidence}
                  </Paper>
                </Box>
              )}

              {finding.cve_ids && finding.cve_ids.length > 0 && (
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    CVE References
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                    {finding.cve_ids.map((cve) => (
                      <Chip
                        key={cve}
                        label={cve}
                        size="small"
                        color="error"
                        variant="outlined"
                        icon={<OpenInNewIcon fontSize="small" />}
                        onClick={() =>
                          window.open(`https://nvd.nist.gov/vuln/detail/${cve}`, "_blank")
                        }
                        sx={{ cursor: "pointer" }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {finding.recommendation && (
                <Box>
                  <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                    Recommendation
                  </Typography>
                  <Typography variant="body2">{finding.recommendation}</Typography>
                </Box>
              )}
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
};

export const NmapFindingsTab: React.FC<NmapFindingsTabProps> = ({
  findings,
  onHostClick,
}) => {
  const theme = useTheme();
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string[]>([]);
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");

  // Get unique categories
  const categories = useMemo(() => {
    return [...new Set(findings.map((f) => f.category))].sort();
  }, [findings]);

  // Count by severity
  const severityCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    findings.forEach((f) => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }, [findings]);

  // Filter and sort findings
  const filteredFindings = useMemo(() => {
    let filtered = [...findings];

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (f) =>
          f.title.toLowerCase().includes(query) ||
          f.description.toLowerCase().includes(query) ||
          (f.host?.toLowerCase() || "").includes(query) ||
          f.service?.toLowerCase().includes(query) ||
          f.category.toLowerCase().includes(query)
      );
    }

    // Severity filter
    if (severityFilter.length > 0) {
      filtered = filtered.filter((f) => severityFilter.includes(f.severity));
    }

    // Category filter
    if (categoryFilter) {
      filtered = filtered.filter((f) => f.category === categoryFilter);
    }

    // Sort
    filtered.sort((a, b) => {
      let comparison = 0;
      switch (sortField) {
        case "severity":
          comparison =
            severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity);
          break;
        case "host":
          comparison = (a.host || "").localeCompare(b.host || "");
          break;
        case "port":
          comparison = (a.port || 0) - (b.port || 0);
          break;
        case "category":
          comparison = a.category.localeCompare(b.category);
          break;
        case "title":
          comparison = a.title.localeCompare(b.title);
          break;
      }
      return sortOrder === "asc" ? comparison : -comparison;
    });

    return filtered;
  }, [findings, searchQuery, severityFilter, categoryFilter, sortField, sortOrder]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  const toggleSeverityFilter = (severity: string) => {
    if (severityFilter.includes(severity)) {
      setSeverityFilter(severityFilter.filter((s) => s !== severity));
    } else {
      setSeverityFilter([...severityFilter, severity]);
    }
  };

  if (findings.length === 0) {
    return (
      <Paper sx={{ p: 4, textAlign: "center" }}>
        <InfoIcon sx={{ fontSize: 48, color: "success.main", mb: 1 }} />
        <Typography variant="h6" gutterBottom>
          No Security Findings
        </Typography>
        <Typography color="text.secondary">
          No vulnerabilities or security issues were detected in this scan.
        </Typography>
      </Paper>
    );
  }

  return (
    <Box>
      {/* Filters */}
      <Box sx={{ mb: 2 }}>
        <Box sx={{ display: "flex", gap: 2, mb: 2, flexWrap: "wrap" }}>
          <TextField
            size="small"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            sx={{ minWidth: 250 }}
            InputProps={{
              startAdornment: (
                <InputAdornment position="start">
                  <SearchIcon fontSize="small" />
                </InputAdornment>
              ),
            }}
          />
          <FormControl size="small" sx={{ minWidth: 150 }}>
            <InputLabel>Category</InputLabel>
            <Select
              value={categoryFilter}
              label="Category"
              onChange={(e) => setCategoryFilter(e.target.value)}
            >
              <MenuItem value="">All Categories</MenuItem>
              {categories.map((cat) => (
                <MenuItem key={cat} value={cat}>
                  {cat}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Box>

        {/* Severity filter chips */}
        <Box sx={{ display: "flex", gap: 1, alignItems: "center", flexWrap: "wrap" }}>
          <FilterIcon fontSize="small" color="action" />
          <Typography variant="body2" color="text.secondary" sx={{ mr: 1 }}>
            Severity:
          </Typography>
          {["critical", "high", "medium", "low", "info"].map((severity) => (
            <Chip
              key={severity}
              label={`${severity.toUpperCase()} (${severityCounts[severity] || 0})`}
              size="small"
              color={
                severityFilter.includes(severity)
                  ? (getSeverityColor(severity) as any)
                  : "default"
              }
              variant={severityFilter.includes(severity) ? "filled" : "outlined"}
              onClick={() => toggleSeverityFilter(severity)}
              sx={{ cursor: "pointer" }}
            />
          ))}
          {severityFilter.length > 0 && (
            <Chip
              label="Clear"
              size="small"
              variant="outlined"
              onClick={() => setSeverityFilter([])}
              sx={{ cursor: "pointer" }}
            />
          )}
        </Box>
      </Box>

      {/* Summary stats */}
      <Paper
        sx={{
          p: 1.5,
          mb: 2,
          display: "flex",
          gap: 3,
          bgcolor: alpha(theme.palette.background.default, 0.5),
        }}
      >
        <Typography variant="body2">
          Showing <strong>{filteredFindings.length}</strong> of{" "}
          <strong>{findings.length}</strong> findings
        </Typography>
        {severityCounts.critical > 0 && (
          <Typography variant="body2" color="error">
            {severityCounts.critical} Critical
          </Typography>
        )}
        {severityCounts.high > 0 && (
          <Typography variant="body2" color="error">
            {severityCounts.high} High
          </Typography>
        )}
        {severityCounts.medium > 0 && (
          <Typography variant="body2" color="warning.main">
            {severityCounts.medium} Medium
          </Typography>
        )}
      </Paper>

      {/* Findings table */}
      <TableContainer component={Paper}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell padding="checkbox" />
              <TableCell>
                <TableSortLabel
                  active={sortField === "severity"}
                  direction={sortField === "severity" ? sortOrder : "asc"}
                  onClick={() => handleSort("severity")}
                >
                  Severity
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === "host"}
                  direction={sortField === "host" ? sortOrder : "asc"}
                  onClick={() => handleSort("host")}
                >
                  Host
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === "port"}
                  direction={sortField === "port" ? sortOrder : "asc"}
                  onClick={() => handleSort("port")}
                >
                  Port
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === "category"}
                  direction={sortField === "category" ? sortOrder : "asc"}
                  onClick={() => handleSort("category")}
                >
                  Category
                </TableSortLabel>
              </TableCell>
              <TableCell>
                <TableSortLabel
                  active={sortField === "title"}
                  direction={sortField === "title" ? sortOrder : "asc"}
                  onClick={() => handleSort("title")}
                >
                  Title
                </TableSortLabel>
              </TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredFindings.map((finding, idx) => (
              <FindingRow
                key={idx}
                finding={finding}
                onHostClick={onHostClick}
              />
            ))}
            {filteredFindings.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} sx={{ textAlign: "center", py: 4 }}>
                  <Typography color="text.secondary">
                    No findings match your filters
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};

export default NmapFindingsTab;
