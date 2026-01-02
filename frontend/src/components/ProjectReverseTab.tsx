import React, { useState, useEffect } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  alpha,
  useTheme,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  CircularProgress,
  Alert,
} from "@mui/material";
import { useNavigate } from "react-router-dom";
import BuildIcon from "@mui/icons-material/Build";
import AndroidIcon from "@mui/icons-material/Android";
import MemoryIcon from "@mui/icons-material/Memory";
import LayersIcon from "@mui/icons-material/Layers";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import DeleteIcon from "@mui/icons-material/Delete";
import VisibilityIcon from "@mui/icons-material/Visibility";
import RefreshIcon from "@mui/icons-material/Refresh";
import { reverseEngineeringClient, REReportSummary } from "../api/client";

interface ProjectReverseTabProps {
  projectId: number;
  projectName: string;
}

const ArrowRightIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 4l-1.41 1.41L16.17 11H4v2h12.17l-5.58 5.59L12 20l8-8z" />
  </svg>
);

const ProjectReverseTab: React.FC<ProjectReverseTabProps> = ({
  projectId,
  projectName,
}) => {
  const theme = useTheme();
  const navigate = useNavigate();
  const [reports, setReports] = useState<REReportSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReports = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await reverseEngineeringClient.listReports({ project_id: projectId, limit: 50 });
      setReports(data);
    } catch (e: any) {
      setError(e.message || "Failed to load reports");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReports();
  }, [projectId]);

  const handleDeleteReport = async (reportId: number) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      await reverseEngineeringClient.deleteReport(reportId);
      loadReports();
    } catch (e: any) {
      setError(e.message || "Failed to delete report");
    }
  };

  const reTools = [
    {
      title: "APK Analysis",
      description: "Analyze Android applications - permissions, components, certificates, attack surface, and obfuscation detection",
      icon: <AndroidIcon sx={{ fontSize: 32 }} />,
      color: "#22c55e",
      tabIndex: 1,
    },
    {
      title: "Binary Analysis",
      description: "Analyze PE (Windows) and ELF (Linux) executables - strings, imports, Rich headers, AI-powered insights",
      icon: <MemoryIcon sx={{ fontSize: 32 }} />,
      color: "#f59e0b",
      tabIndex: 0,
    },
    {
      title: "Docker Inspector",
      description: "Container security analysis - escape vectors, privilege escalation, secrets in layers, supply chain risks, AI threat assessment",
      icon: <LayersIcon sx={{ fontSize: 32 }} />,
      color: "#06b6d4",
      tabIndex: 2,
      badge: "🔴 Offensive",
    },
  ];

  const getAnalysisIcon = (type: string) => {
    switch (type) {
      case 'apk': return <AndroidIcon sx={{ color: "#22c55e" }} />;
      case 'binary': return <MemoryIcon sx={{ color: "#f59e0b" }} />;
      case 'docker': return <LayersIcon sx={{ color: "#06b6d4" }} />;
      default: return <BuildIcon />;
    }
  };

  const getRiskColor = (level?: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return '#ef4444';
      case 'high': return '#f97316';
      case 'medium': return '#eab308';
      case 'low': return '#22c55e';
      case 'clean': return '#3b82f6';
      default: return '#6b7280';
    }
  };

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `linear-gradient(135deg, #f97316 0%, #ea580c 100%)`,
              color: "#fff",
            }}
          >
            <BuildIcon sx={{ fontSize: 32 }} />
          </Box>
          <Box>
            <Typography variant="h5" fontWeight={700}>
              Reverse Engineering for {projectName}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Analyze APKs, binaries, and Docker images with AI-powered security insights
            </Typography>
          </Box>
        </Box>
      </Box>

      {/* Tool Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {reTools.map((tool) => (
          <Grid item xs={12} md={4} key={tool.title}>
            <Card
              sx={{
                height: "100%",
                background: `linear-gradient(135deg, ${alpha(tool.color, 0.08)} 0%, ${alpha(tool.color, 0.03)} 100%)`,
                border: `1px solid ${alpha(tool.color, 0.2)}`,
                borderRadius: 3,
                transition: "all 0.3s ease",
                cursor: "pointer",
                "&:hover": {
                  transform: "translateY(-4px)",
                  boxShadow: `0 10px 30px ${alpha(tool.color, 0.2)}`,
                  border: `1px solid ${alpha(tool.color, 0.4)}`,
                },
              }}
              onClick={() => navigate(`/reverse?projectId=${projectId}&projectName=${encodeURIComponent(projectName)}&tab=${tool.tabIndex}`)}
            >
              <CardContent sx={{ p: 3, height: "100%", display: "flex", flexDirection: "column" }}>
                <Box
                  sx={{
                    width: 56,
                    height: 56,
                    borderRadius: 2,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background: `linear-gradient(135deg, ${tool.color} 0%, ${alpha(tool.color, 0.8)} 100%)`,
                    color: "#fff",
                    mb: 2,
                  }}
                >
                  {tool.icon}
                </Box>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Typography variant="h6" fontWeight={700}>
                    {tool.title}
                  </Typography>
                  {tool.badge && (
                    <Chip
                      label={tool.badge}
                      size="small"
                      sx={{
                        bgcolor: alpha("#ef4444", 0.15),
                        color: "#ef4444",
                        fontWeight: 600,
                        fontSize: "0.7rem",
                        height: 22,
                      }}
                    />
                  )}
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ flex: 1, mb: 2 }}>
                  {tool.description}
                </Typography>
                <Button
                  variant="outlined"
                  size="small"
                  endIcon={<ArrowRightIcon />}
                  sx={{
                    borderColor: alpha(tool.color, 0.5),
                    color: tool.color,
                    "&:hover": {
                      borderColor: tool.color,
                      bgcolor: alpha(tool.color, 0.1),
                    },
                  }}
                >
                  Launch Tool
                </Button>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      {/* Project Reports */}
      <Paper sx={{ p: 3, bgcolor: alpha(theme.palette.background.paper, 0.8), borderRadius: 3, mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
          <Typography variant="h6" fontWeight={700}>
            Reverse Engineering Reports for {projectName}
          </Typography>
          <Tooltip title="Refresh reports">
            <IconButton onClick={loadReports} disabled={loading}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
        )}

        {loading ? (
          <Box sx={{ display: "flex", justifyContent: "center", py: 4 }}>
            <CircularProgress />
          </Box>
        ) : reports.length === 0 ? (
          <Alert severity="info">
            No reverse engineering reports for this project yet. Use the tools above to analyze files and save reports.
          </Alert>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Type</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Title</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Risk</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Date</TableCell>
                  <TableCell sx={{ fontWeight: 700 }} align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {reports.map((report) => (
                  <TableRow key={report.id} hover>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        {getAnalysisIcon(report.analysis_type)}
                        <Typography variant="body2" sx={{ textTransform: "capitalize" }}>
                          {report.analysis_type}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {report.title}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      {report.risk_level && (
                        <Chip
                          label={report.risk_level}
                          size="small"
                          sx={{
                            bgcolor: alpha(getRiskColor(report.risk_level), 0.1),
                            color: getRiskColor(report.risk_level),
                            fontWeight: 600,
                          }}
                        />
                      )}
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {new Date(report.created_at).toLocaleDateString()}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      <Tooltip title="View report">
                        <IconButton
                          size="small"
                          onClick={() => navigate(`/reverse?projectId=${projectId}&projectName=${encodeURIComponent(projectName)}&reportId=${report.id}`)}
                        >
                          <VisibilityIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete report">
                        <IconButton
                          size="small"
                          color="error"
                          onClick={() => handleDeleteReport(report.id)}
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
      </Paper>

      {/* Full Hub Link */}
      <Card
        sx={{
          display: "flex",
          alignItems: "center",
          p: 3,
          background: `linear-gradient(135deg, ${alpha("#f97316", 0.08)} 0%, ${alpha("#ea580c", 0.05)} 100%)`,
          border: `1px solid ${alpha("#f97316", 0.2)}`,
          borderRadius: 3,
          cursor: "pointer",
          transition: "all 0.3s ease",
          "&:hover": {
            transform: "translateY(-4px)",
            boxShadow: `0 10px 30px ${alpha("#f97316", 0.2)}`,
            border: `1px solid ${alpha("#f97316", 0.4)}`,
          },
        }}
        onClick={() => navigate(`/reverse?projectId=${projectId}&projectName=${encodeURIComponent(projectName)}`)}
      >
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: 2,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: `linear-gradient(135deg, #f97316 0%, #ea580c 100%)`,
            color: "#fff",
            mr: 3,
          }}
        >
          <BuildIcon sx={{ fontSize: 32 }} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="h6"
            fontWeight={700}
            sx={{
              background: `linear-gradient(135deg, #fb923c 0%, #f97316 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              mb: 0.5,
            }}
          >
            Open Full Reverse Engineering Hub
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Access all reverse engineering tools in the dedicated hub with history, exports, and more
          </Typography>
        </Box>
        <Box sx={{ color: "#fb923c" }}>
          <ArrowRightIcon />
        </Box>
      </Card>

      {/* Learning Link */}
      <Card
        sx={{
          mt: 3,
          display: "flex",
          alignItems: "center",
          p: 3,
          background: `linear-gradient(135deg, ${alpha("#6366f1", 0.08)} 0%, ${alpha("#8b5cf6", 0.05)} 100%)`,
          border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
          borderRadius: 3,
          cursor: "pointer",
          transition: "all 0.3s ease",
          "&:hover": {
            transform: "translateY(-4px)",
            boxShadow: `0 10px 30px ${alpha("#8b5cf6", 0.2)}`,
            border: `1px solid ${alpha("#8b5cf6", 0.4)}`,
          },
        }}
        onClick={() => navigate("/learn/apk-analysis")}
      >
        <Box
          sx={{
            width: 56,
            height: 56,
            borderRadius: 2,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)`,
            color: "#fff",
            mr: 3,
          }}
        >
          <MenuBookIcon sx={{ fontSize: 32 }} />
        </Box>
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="h6"
            fontWeight={700}
            sx={{
              background: `linear-gradient(135deg, #a78bfa 0%, #8b5cf6 100%)`,
              backgroundClip: "text",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              mb: 0.5,
            }}
          >
            APK Analysis Guide
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Learn about APK structure, permissions, attack surface analysis, and obfuscation detection
          </Typography>
        </Box>
        <Box sx={{ color: "#a78bfa" }}>
          <ArrowRightIcon />
        </Box>
      </Card>
    </Box>
  );
};

export default ProjectReverseTab;
