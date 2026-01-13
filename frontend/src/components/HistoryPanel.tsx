import React, { useState, useEffect, useCallback } from "react";
import {
  Box,
  Typography,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemIcon,
  TextField,
  InputAdornment,
  Chip,
  Tooltip,
  CircularProgress,
  Alert,
  Divider,
  Menu,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Badge,
} from "@mui/material";
import {
  Search as SearchIcon,
  History as HistoryIcon,
  Delete as DeleteIcon,
  DeleteSweep as ClearAllIcon,
  Refresh as RefreshIcon,
  FilterList as FilterIcon,
  MoreVert as MoreIcon,
  PlayArrow as ReplayIcon,
  CheckCircle as SuccessIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Timer as TimerIcon,
  DataUsage as SizeIcon,
} from "@mui/icons-material";
import {
  apiCollections,
  APIRequestHistoryEntry,
  APIRequestHistoryStats,
} from "../api/client";

// HTTP Method colors
const getMethodColor = (method: string) => {
  switch (method?.toUpperCase()) {
    case "GET": return "#61affe";
    case "POST": return "#49cc90";
    case "PUT": return "#fca130";
    case "DELETE": return "#f93e3e";
    case "PATCH": return "#50e3c2";
    case "OPTIONS": return "#0d5aa7";
    case "HEAD": return "#9012fe";
    default: return "#999";
  }
};

// Status color helper
const getStatusColor = (status?: number) => {
  if (!status) return "text.secondary";
  if (status >= 200 && status < 300) return "success.main";
  if (status >= 300 && status < 400) return "warning.main";
  if (status >= 400) return "error.main";
  return "text.secondary";
};

// Format bytes
const formatBytes = (bytes?: number) => {
  if (!bytes) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

// Format time
const formatTime = (ms?: number) => {
  if (!ms) return "-";
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
};

// Format date
const formatDate = (dateStr?: string) => {
  if (!dateStr) return "";
  const date = new Date(dateStr);
  const now = new Date();
  const diff = now.getTime() - date.getTime();
  
  // Less than 1 minute
  if (diff < 60000) return "Just now";
  // Less than 1 hour
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  // Less than 24 hours
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  // Less than 7 days
  if (diff < 604800000) return `${Math.floor(diff / 86400000)}d ago`;
  // Otherwise show date
  return date.toLocaleDateString();
};

interface HistoryPanelProps {
  onSelectEntry?: (entry: APIRequestHistoryEntry) => void;
  onReplayEntry?: (entry: APIRequestHistoryEntry) => void;
  compact?: boolean;
}

export default function HistoryPanel({
  onSelectEntry,
  onReplayEntry,
  compact = false,
}: HistoryPanelProps) {
  // State
  const [entries, setEntries] = useState<APIRequestHistoryEntry[]>([]);
  const [stats, setStats] = useState<APIRequestHistoryStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const limit = 50;

  // Dialogs
  const [clearDialogOpen, setClearDialogOpen] = useState(false);
  const [clearOlderDays, setClearOlderDays] = useState<number | "">("");
  const [selectedEntry, setSelectedEntry] = useState<APIRequestHistoryEntry | null>(null);
  const [menuAnchorEl, setMenuAnchorEl] = useState<null | HTMLElement>(null);
  const [contextEntry, setContextEntry] = useState<APIRequestHistoryEntry | null>(null);

  // Load history
  const loadHistory = useCallback(async (resetOffset = false) => {
    setLoading(true);
    setError(null);
    
    try {
      const newOffset = resetOffset ? 0 : offset;
      const response = await apiCollections.listHistory({
        limit,
        offset: newOffset,
        method: methodFilter || undefined,
        url: searchQuery || undefined,
        status: statusFilter as "success" | "error" | "redirect" | undefined,
      });
      
      setEntries(response.entries);
      setTotal(response.total);
      if (resetOffset) setOffset(0);
    } catch (err: any) {
      setError(err.message || "Failed to load history");
    } finally {
      setLoading(false);
    }
  }, [offset, methodFilter, searchQuery, statusFilter]);

  // Load stats
  const loadStats = useCallback(async () => {
    try {
      const response = await apiCollections.getHistoryStats();
      setStats({
        total_requests: response.total_requests,
        methods: response.methods,
        success_count: response.success_count,
        error_count: response.error_count,
        success_rate: response.success_rate,
        avg_response_time_ms: response.avg_response_time_ms,
      });
    } catch (err) {
      console.error("Failed to load stats:", err);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadHistory(true);
    loadStats();
  }, []);

  // Reload on filter change
  useEffect(() => {
    loadHistory(true);
  }, [methodFilter, statusFilter]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      loadHistory(true);
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Handle delete entry
  const handleDeleteEntry = async (entry: APIRequestHistoryEntry) => {
    if (!entry.id) return;
    
    try {
      await apiCollections.deleteHistoryEntry(entry.id);
      setEntries(prev => prev.filter(e => e.id !== entry.id));
      setTotal(prev => prev - 1);
      loadStats();
    } catch (err: any) {
      setError(err.message || "Failed to delete entry");
    }
  };

  // Handle clear history
  const handleClearHistory = async () => {
    try {
      const options = clearOlderDays ? { older_than_days: Number(clearOlderDays) } : undefined;
      await apiCollections.clearHistory(options);
      setClearDialogOpen(false);
      setClearOlderDays("");
      loadHistory(true);
      loadStats();
    } catch (err: any) {
      setError(err.message || "Failed to clear history");
    }
  };

  // Handle entry click
  const handleEntryClick = (entry: APIRequestHistoryEntry) => {
    setSelectedEntry(entry);
    onSelectEntry?.(entry);
  };

  // Handle context menu
  const handleContextMenu = (event: React.MouseEvent, entry: APIRequestHistoryEntry) => {
    event.preventDefault();
    event.stopPropagation();
    setContextEntry(entry);
    setMenuAnchorEl(event.currentTarget as HTMLElement);
  };

  // Get URL path for display
  const getDisplayUrl = (url: string) => {
    try {
      const urlObj = new URL(url);
      return urlObj.pathname + urlObj.search;
    } catch {
      return url;
    }
  };

  return (
    <Box sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <Box sx={{ p: 1.5, borderBottom: 1, borderColor: "divider" }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
          <HistoryIcon fontSize="small" color="primary" />
          <Typography variant="subtitle1" fontWeight="medium">
            History
          </Typography>
          <Box sx={{ flexGrow: 1 }} />
          <Tooltip title="Refresh">
            <IconButton size="small" onClick={() => loadHistory(true)} disabled={loading}>
              <RefreshIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Clear History">
            <IconButton size="small" onClick={() => setClearDialogOpen(true)}>
              <ClearAllIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Box>

        {/* Stats */}
        {stats && !compact && (
          <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 1 }}>
            <Chip
              size="small"
              label={`${stats.total_requests} requests`}
              variant="outlined"
            />
            <Chip
              size="small"
              icon={<SuccessIcon sx={{ fontSize: 14 }} />}
              label={`${stats.success_rate.toFixed(0)}%`}
              color={stats.success_rate > 80 ? "success" : stats.success_rate > 50 ? "warning" : "error"}
              variant="outlined"
            />
            {stats.avg_response_time_ms && (
              <Chip
                size="small"
                icon={<TimerIcon sx={{ fontSize: 14 }} />}
                label={formatTime(stats.avg_response_time_ms)}
                variant="outlined"
              />
            )}
          </Box>
        )}

        {/* Search */}
        <TextField
          size="small"
          fullWidth
          placeholder="Search URLs..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon fontSize="small" />
              </InputAdornment>
            ),
          }}
          sx={{ mb: 1 }}
        />

        {/* Filters */}
        <Box sx={{ display: "flex", gap: 1 }}>
          <FormControl size="small" sx={{ minWidth: 80 }}>
            <InputLabel>Method</InputLabel>
            <Select
              value={methodFilter}
              onChange={(e) => setMethodFilter(e.target.value)}
              label="Method"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="GET">GET</MenuItem>
              <MenuItem value="POST">POST</MenuItem>
              <MenuItem value="PUT">PUT</MenuItem>
              <MenuItem value="PATCH">PATCH</MenuItem>
              <MenuItem value="DELETE">DELETE</MenuItem>
            </Select>
          </FormControl>
          <FormControl size="small" sx={{ minWidth: 80 }}>
            <InputLabel>Status</InputLabel>
            <Select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              label="Status"
            >
              <MenuItem value="">All</MenuItem>
              <MenuItem value="success">Success (2xx)</MenuItem>
              <MenuItem value="redirect">Redirect (3xx)</MenuItem>
              <MenuItem value="error">Error (4xx/5xx)</MenuItem>
            </Select>
          </FormControl>
        </Box>
      </Box>

      {/* Error */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ m: 1 }}>
          {error}
        </Alert>
      )}

      {/* Loading */}
      {loading && (
        <Box sx={{ display: "flex", justifyContent: "center", p: 2 }}>
          <CircularProgress size={24} />
        </Box>
      )}

      {/* History List */}
      <List
        sx={{
          flexGrow: 1,
          overflow: "auto",
          p: 0,
          "& .MuiListItemButton-root": {
            py: 0.75,
          },
        }}
      >
        {entries.length === 0 && !loading ? (
          <Box sx={{ p: 2, textAlign: "center" }}>
            <Typography variant="body2" color="text.secondary">
              No history yet. Execute some requests to see them here.
            </Typography>
          </Box>
        ) : (
          entries.map((entry) => (
            <ListItem
              key={entry.id}
              disablePadding
              secondaryAction={
                <IconButton
                  edge="end"
                  size="small"
                  onClick={(e) => handleContextMenu(e, entry)}
                >
                  <MoreIcon fontSize="small" />
                </IconButton>
              }
              sx={{
                borderBottom: 1,
                borderColor: "divider",
                bgcolor: selectedEntry?.id === entry.id ? "action.selected" : "transparent",
              }}
            >
              <ListItemButton onClick={() => handleEntryClick(entry)}>
                <ListItemIcon sx={{ minWidth: 48 }}>
                  <Chip
                    label={entry.method}
                    size="small"
                    sx={{
                      bgcolor: getMethodColor(entry.method),
                      color: "white",
                      fontWeight: "bold",
                      fontSize: "0.65rem",
                      height: 20,
                      minWidth: 40,
                    }}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                      <Typography
                        variant="body2"
                        sx={{
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                          maxWidth: compact ? 120 : 180,
                        }}
                      >
                        {getDisplayUrl(entry.url)}
                      </Typography>
                    </Box>
                  }
                  secondary={
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1, mt: 0.25 }}>
                      {entry.status_code && (
                        <Typography
                          variant="caption"
                          sx={{
                            color: getStatusColor(entry.status_code),
                            fontWeight: "medium",
                          }}
                        >
                          {entry.status_code}
                        </Typography>
                      )}
                      {entry.error && (
                        <Tooltip title={entry.error}>
                          <ErrorIcon sx={{ fontSize: 12, color: "error.main" }} />
                        </Tooltip>
                      )}
                      {entry.response_time_ms && (
                        <Typography variant="caption" color="text.secondary">
                          {formatTime(entry.response_time_ms)}
                        </Typography>
                      )}
                      <Typography variant="caption" color="text.secondary">
                        {formatDate(entry.executed_at)}
                      </Typography>
                    </Box>
                  }
                />
              </ListItemButton>
            </ListItem>
          ))
        )}
      </List>

      {/* Load more */}
      {entries.length < total && (
        <Box sx={{ p: 1, textAlign: "center", borderTop: 1, borderColor: "divider" }}>
          <Button
            size="small"
            onClick={() => {
              setOffset(prev => prev + limit);
              loadHistory();
            }}
            disabled={loading}
          >
            Load More ({entries.length} of {total})
          </Button>
        </Box>
      )}

      {/* Context Menu */}
      <Menu
        anchorEl={menuAnchorEl}
        open={Boolean(menuAnchorEl)}
        onClose={() => setMenuAnchorEl(null)}
      >
        <MenuItem
          onClick={() => {
            if (contextEntry) {
              onReplayEntry?.(contextEntry);
            }
            setMenuAnchorEl(null);
          }}
        >
          <ListItemIcon>
            <ReplayIcon fontSize="small" />
          </ListItemIcon>
          Replay Request
        </MenuItem>
        <MenuItem
          onClick={() => {
            if (contextEntry) {
              handleDeleteEntry(contextEntry);
            }
            setMenuAnchorEl(null);
          }}
        >
          <ListItemIcon>
            <DeleteIcon fontSize="small" color="error" />
          </ListItemIcon>
          Delete
        </MenuItem>
      </Menu>

      {/* Clear Dialog */}
      <Dialog open={clearDialogOpen} onClose={() => setClearDialogOpen(false)}>
        <DialogTitle>Clear History</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            This will permanently delete history entries.
          </Typography>
          <TextField
            fullWidth
            type="number"
            label="Delete entries older than (days)"
            value={clearOlderDays}
            onChange={(e) => setClearOlderDays(e.target.value ? parseInt(e.target.value) : "")}
            placeholder="Leave empty to delete all"
            helperText="Leave empty to clear all history"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setClearDialogOpen(false)}>Cancel</Button>
          <Button onClick={handleClearHistory} color="error" variant="contained">
            Clear History
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
