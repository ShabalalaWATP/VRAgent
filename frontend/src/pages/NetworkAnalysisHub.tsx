import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Alert,
  CircularProgress,
  alpha,
  useTheme,
  Tooltip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import RadarIcon from "@mui/icons-material/Radar";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadIcon from "@mui/icons-material/Download";
import VisibilityIcon from "@mui/icons-material/Visibility";
import RefreshIcon from "@mui/icons-material/Refresh";
import DescriptionIcon from "@mui/icons-material/Description";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ArticleIcon from "@mui/icons-material/Article";
import HubIcon from "@mui/icons-material/Hub";
import { apiClient, SavedNetworkReport } from "../api/client";

const NetworkAnalysisHub: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [reports, setReports] = useState<SavedNetworkReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<number | null>(null);
  const [exportAnchorEl, setExportAnchorEl] = useState<null | HTMLElement>(null);
  const [exportReportId, setExportReportId] = useState<number | null>(null);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.getNetworkReports();
      setReports(data);
    } catch (err: any) {
      setError(err.message || "Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, []);

  const handleDelete = async (reportId: number) => {
    try {
      await apiClient.deleteNetworkReport(reportId);
      setReports(reports.filter((r) => r.id !== reportId));
      setDeleteConfirm(null);
    } catch (err: any) {
      setError(err.message || "Failed to delete report");
    }
  };

  const handleExportClick = (event: React.MouseEvent<HTMLElement>, reportId: number) => {
    setExportAnchorEl(event.currentTarget);
    setExportReportId(reportId);
  };

  const handleExportClose = () => {
    setExportAnchorEl(null);
    setExportReportId(null);
  };

  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    if (!exportReportId) return;
    try {
      const blob = await apiClient.exportNetworkReport(exportReportId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `network_report_${exportReportId}.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
    handleExportClose();
  };

  const getRiskColor = (level: string | null) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "#dc2626";
      case "high":
        return "#ea580c";
      case "medium":
        return "#ca8a04";
      case "low":
        return "#16a34a";
      default:
        return "#6b7280";
    }
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleString();
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <HubIcon sx={{ fontSize: 40, color: "primary.main" }} />
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Network Analysis
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Analyze network traffic captures and scan results with AI-powered security insights
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Tool Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* PCAP Analyzer */}
        <Grid item xs={12} md={6}>
          <Card
            sx={{
              height: "100%",
              background: `linear-gradient(135deg, ${alpha("#06b6d4", 0.1)} 0%, ${alpha("#0891b2", 0.05)} 100%)`,
              border: `1px solid ${alpha("#06b6d4", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#06b6d4", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <NetworkCheckIcon sx={{ fontSize: 32, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h6" fontWeight={700}>
                    PCAP Analyzer
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Wireshark Packet Capture Analysis
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Upload .pcap or .pcapng files from Wireshark, tcpdump, or other packet capture tools.
                Analyzes protocols, detects suspicious traffic patterns, credential exposure, and
                potential attack indicators with Gemini AI.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label=".pcap" size="small" variant="outlined" />
                <Chip label=".pcapng" size="small" variant="outlined" />
                <Chip label=".cap" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to="/network/pcap"
                variant="contained"
                fullWidth
                sx={{
                  background: `linear-gradient(135deg, #06b6d4 0%, #0891b2 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #0891b2 0%, #0e7490 100%)`,
                  },
                }}
              >
                Open PCAP Analyzer
              </Button>
            </CardContent>
          </Card>
        </Grid>

        {/* Nmap Analyzer */}
        <Grid item xs={12} md={6}>
          <Card
            sx={{
              height: "100%",
              background: `linear-gradient(135deg, ${alpha("#8b5cf6", 0.1)} 0%, ${alpha("#7c3aed", 0.05)} 100%)`,
              border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                transform: "translateY(-4px)",
                boxShadow: `0 8px 30px ${alpha("#8b5cf6", 0.3)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 2,
                    background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                  }}
                >
                  <RadarIcon sx={{ fontSize: 32, color: "white" }} />
                </Box>
                <Box>
                  <Typography variant="h6" fontWeight={700}>
                    Nmap Analyzer
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Network Scan Results Analysis
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                Upload Nmap scan output files (XML, grepable, or normal format). Identifies open
                ports, vulnerable services, outdated software, misconfigurations, and provides
                prioritized remediation recommendations.
              </Typography>
              <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mb: 3 }}>
                <Chip label=".xml" size="small" variant="outlined" />
                <Chip label=".nmap" size="small" variant="outlined" />
                <Chip label=".gnmap" size="small" variant="outlined" />
              </Box>
              <Button
                component={Link}
                to="/network/nmap"
                variant="contained"
                fullWidth
                sx={{
                  background: `linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%)`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)`,
                  },
                }}
              >
                Open Nmap Analyzer
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Saved Reports */}
      <Box sx={{ mb: 2, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Typography variant="h5" fontWeight={600}>
          Saved Reports
        </Typography>
        <Button startIcon={<RefreshIcon />} onClick={fetchReports} disabled={loading}>
          Refresh
        </Button>
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {loading ? (
        <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
          <CircularProgress />
        </Box>
      ) : reports.length === 0 ? (
        <Paper sx={{ p: 4, textAlign: "center" }}>
          <Typography color="text.secondary">
            No saved reports yet. Run a PCAP or Nmap analysis to get started.
          </Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Type</TableCell>
                <TableCell>Title</TableCell>
                <TableCell>Files</TableCell>
                <TableCell>Risk Level</TableCell>
                <TableCell>Findings</TableCell>
                <TableCell>Created</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {reports.map((report) => (
                <TableRow key={report.id} hover>
                  <TableCell>
                    <Chip
                      label={report.analysis_type.toUpperCase()}
                      size="small"
                      sx={{
                        bgcolor:
                          report.analysis_type === "pcap"
                            ? alpha("#06b6d4", 0.15)
                            : alpha("#8b5cf6", 0.15),
                        color: report.analysis_type === "pcap" ? "#0891b2" : "#7c3aed",
                        fontWeight: 600,
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight={500}>
                      {report.title}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography
                      variant="caption"
                      color="text.secondary"
                      sx={{
                        maxWidth: 200,
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                        display: "block",
                      }}
                    >
                      {report.filename || "-"}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {report.risk_level ? (
                      <Chip
                        label={report.risk_level}
                        size="small"
                        sx={{
                          bgcolor: alpha(getRiskColor(report.risk_level), 0.15),
                          color: getRiskColor(report.risk_level),
                          fontWeight: 600,
                        }}
                      />
                    ) : (
                      "-"
                    )}
                  </TableCell>
                  <TableCell>{report.findings_count}</TableCell>
                  <TableCell>
                    <Typography variant="caption">{formatDate(report.created_at)}</Typography>
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="View Report">
                      <IconButton
                        size="small"
                        onClick={() =>
                          navigate(
                            `/network/${report.analysis_type}?reportId=${report.id}`
                          )
                        }
                      >
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Export">
                      <IconButton
                        size="small"
                        onClick={(e) => handleExportClick(e, report.id)}
                      >
                        <DownloadIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        size="small"
                        color="error"
                        onClick={() => setDeleteConfirm(report.id)}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Export Menu */}
      <Menu
        anchorEl={exportAnchorEl}
        open={Boolean(exportAnchorEl)}
        onClose={handleExportClose}
      >
        <MenuItem onClick={() => handleExport("markdown")}>
          <ListItemIcon>
            <DescriptionIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Markdown (.md)</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExport("pdf")}>
          <ListItemIcon>
            <PictureAsPdfIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>PDF (.pdf)</ListItemText>
        </MenuItem>
        <MenuItem onClick={() => handleExport("docx")}>
          <ListItemIcon>
            <ArticleIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Word (.docx)</ListItemText>
        </MenuItem>
      </Menu>

      {/* Delete Confirmation */}
      <Dialog open={deleteConfirm !== null} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Delete Report?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete this report? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            onClick={() => deleteConfirm && handleDelete(deleteConfirm)}
            color="error"
            variant="contained"
          >
            Delete
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default NetworkAnalysisHub;
