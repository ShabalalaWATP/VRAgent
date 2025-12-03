import { useParams, Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Grid,
  IconButton,
  Paper,
  Skeleton,
  Stack,
  Tab,
  Tabs,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  Theme,
  keyframes,
  Snackbar,
  Slide,
  SlideProps,
} from "@mui/material";
import { useState } from "react";
import UploadCodeForm from "../components/UploadCodeForm";
import CloneRepoForm from "../components/CloneRepoForm";
import ScanProgress from "../components/ScanProgress";
import { api } from "../api/client";
import MenuBookIcon from "@mui/icons-material/MenuBook";

// Animations
const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; transform: scale(1); }
  50% { opacity: 0.8; transform: scale(1.05); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
  50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.6), 0 0 60px rgba(34, 211, 238, 0.3); }
`;

// Icons
const BackIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z" />
  </svg>
);

const ScanIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
  </svg>
);

const ReportIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z" />
  </svg>
);

const GitIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M2.6 10.59L8.38 4.8l1.69 1.7c-.24.85.15 1.78.93 2.23v5.54c-.6.34-1 .99-1 1.73 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.39-1-1.73V9.41l1.69 1.7c-.24.85.15 1.78.93 2.23v5.54c-.6.34-1 .99-1 1.73 0 1.1.9 2 2 2s2-.9 2-2c0-.74-.4-1.39-1-1.73v-5.54c.77-.46 1.16-1.38.93-2.23l1.69-1.7 5.78 5.79c.56.56.56 1.47 0 2.03L14.03 21.4c-.56.56-1.47.56-2.03 0L2.6 12.62c-.56-.56-.56-1.47 0-2.03z" />
  </svg>
);

const ArrowRightIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
  </svg>
);

const DeleteIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
  </svg>
);

const ShieldIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
  </svg>
);

// Upload/Clone icons
const UploadIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16h6v-6h4l-7-7-7 7h4zm-4 2h14v2H5z" />
  </svg>
);

const CloneIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-2 10h-4v4h-2v-4H7v-2h4V7h2v4h4v2z" />
  </svg>
);

// Severity color helper
const getSeverityColor = (severity: string, theme: Theme) => {
  const colors: Record<string, { bg: string; text: string; glow: string }> = {
    critical: { 
      bg: alpha(theme.palette.error.main, 0.15), 
      text: theme.palette.error.main,
      glow: alpha(theme.palette.error.main, 0.3)
    },
    high: { 
      bg: alpha("#f97316", 0.15), 
      text: "#f97316",
      glow: alpha("#f97316", 0.3)
    },
    medium: { 
      bg: alpha(theme.palette.warning.main, 0.15), 
      text: theme.palette.warning.main,
      glow: alpha(theme.palette.warning.main, 0.3)
    },
    low: { 
      bg: alpha(theme.palette.info.main, 0.15), 
      text: theme.palette.info.main,
      glow: alpha(theme.palette.info.main, 0.3)
    },
  };
  return colors[severity.toLowerCase()] || { 
    bg: alpha(theme.palette.grey[500], 0.15), 
    text: theme.palette.grey[500],
    glow: alpha(theme.palette.grey[500], 0.3)
  };
};

// Risk score color helper
const getRiskColor = (score: number | null | undefined, theme: Theme) => {
  if (score === null || score === undefined) return theme.palette.grey[500];
  if (score >= 80) return theme.palette.error.main;
  if (score >= 60) return "#f97316";
  if (score >= 40) return theme.palette.warning.main;
  return theme.palette.success.main;
};

// Tabbed Code Source Card component with glassmorphism
interface CodeSourceCardProps {
  projectId: number;
  onSuccess: () => void;
}

function CodeSourceCard({ projectId, onSuccess }: CodeSourceCardProps) {
  const [activeTab, setActiveTab] = useState(0);
  const theme = useTheme();

  return (
    <Card 
      sx={{ 
        height: "100%",
        background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
        backdropFilter: "blur(20px)",
        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        transition: "all 0.3s ease",
        "&:hover": {
          border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}`,
          boxShadow: `0 8px 32px ${alpha(theme.palette.primary.main, 0.15)}`,
        },
      }}
    >
      <CardContent sx={{ p: 0, height: "100%", display: "flex", flexDirection: "column" }}>
        <Box 
          sx={{ 
            borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            background: alpha(theme.palette.background.paper, 0.5),
          }}
        >
          <Tabs 
            value={activeTab} 
            onChange={(_, newValue) => setActiveTab(newValue)}
            sx={{ 
              px: 2,
              "& .MuiTabs-indicator": {
                height: 3,
                borderRadius: "3px 3px 0 0",
                background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              },
              "& .MuiTab-root": {
                textTransform: "none",
                fontWeight: 600,
                minHeight: 56,
                transition: "all 0.3s ease",
                "&.Mui-selected": {
                  color: theme.palette.primary.main,
                },
              }
            }}
          >
            <Tab icon={<UploadIcon />} iconPosition="start" label="Upload Code" />
            <Tab icon={<CloneIcon />} iconPosition="start" label="Clone Repo" />
          </Tabs>
        </Box>
        <Box sx={{ p: 3, flexGrow: 1 }}>
          {activeTab === 0 && (
            <UploadCodeForm
              projectId={projectId}
              onUploaded={onSuccess}
            />
          )}
          {activeTab === 1 && (
            <CloneRepoForm
              projectId={projectId}
              onCloneSuccess={onSuccess}
            />
          )}
        </Box>
      </CardContent>
    </Card>
  );
}

export default function ProjectDetailPage() {
  const { projectId } = useParams();
  const id = Number(projectId);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const theme = useTheme();
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [reportToDelete, setReportToDelete] = useState<{ id: number; date: string } | null>(null);
  const [scanCompleteSnackbar, setScanCompleteSnackbar] = useState(false);

  const projectQuery = useQuery({
    queryKey: ["project", id],
    queryFn: () => api.getProject(id),
    enabled: !!id,
  });

  const reportsQuery = useQuery({
    queryKey: ["reports", id],
    queryFn: () => api.getReports(id),
    enabled: !!id,
  });

  const scanMutation = useMutation({
    mutationFn: () => api.triggerScan(id),
    onSuccess: (data) => {
      if (data?.id) {
        setActiveScanId(data.id);
      }
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (reportId: number) => api.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports", id] });
      setDeleteDialogOpen(false);
      setReportToDelete(null);
    },
  });

  const handleDeleteClick = (reportId: number, reportDate: string) => {
    setReportToDelete({ id: reportId, date: reportDate });
    setDeleteDialogOpen(true);
  };

  const handleDeleteConfirm = () => {
    if (reportToDelete) {
      deleteReportMutation.mutate(reportToDelete.id);
    }
  };

  const handleDeleteCancel = () => {
    setDeleteDialogOpen(false);
    setReportToDelete(null);
  };

  const handleScanComplete = () => {
    setActiveScanId(null);
    setScanCompleteSnackbar(true);
    queryClient.invalidateQueries({ queryKey: ["reports", id] });
  };

  if (!id) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        Invalid project ID
      </Alert>
    );
  }

  return (
    <Box>
      {/* Back Navigation */}
      <Button
        startIcon={<BackIcon />}
        onClick={() => navigate("/")}
        sx={{ 
          mb: 3, 
          color: "text.secondary",
          "&:hover": {
            color: "primary.main",
            background: alpha(theme.palette.primary.main, 0.05),
          },
        }}
      >
        Back to Projects
      </Button>

      {/* Loading State */}
      {projectQuery.isLoading && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Skeleton variant="text" width="40%" height={40} />
            <Skeleton variant="text" width="60%" />
            <Skeleton variant="text" width="30%" sx={{ mt: 2 }} />
          </CardContent>
        </Card>
      )}

      {/* Error State */}
      {projectQuery.isError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {(projectQuery.error as Error).message}
        </Alert>
      )}

      {/* Project Header Card - Glassmorphism Style */}
      {projectQuery.data && (
        <Card
          sx={{
            mb: 4,
            position: "relative",
            overflow: "hidden",
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            "&::before": {
              content: '""',
              position: "absolute",
              top: 0,
              left: 0,
              right: 0,
              height: 4,
              background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            },
          }}
        >
          {/* Floating particles background */}
          <Box
            sx={{
              position: "absolute",
              top: 0,
              right: 0,
              bottom: 0,
              width: "40%",
              overflow: "hidden",
              opacity: 0.5,
              pointerEvents: "none",
            }}
          >
            {[...Array(5)].map((_, i) => (
              <Box
                key={i}
                sx={{
                  position: "absolute",
                  width: 60 + i * 20,
                  height: 60 + i * 20,
                  borderRadius: "50%",
                  background: `radial-gradient(circle, ${alpha(theme.palette.primary.main, 0.1)} 0%, transparent 70%)`,
                  right: `${10 + i * 15}%`,
                  top: `${20 + (i % 3) * 20}%`,
                  animation: `${float} ${3 + i}s ease-in-out infinite`,
                  animationDelay: `${i * 0.5}s`,
                }}
              />
            ))}
          </Box>

          <CardContent sx={{ p: 4, position: "relative", zIndex: 1 }}>
            <Stack direction="row" alignItems="flex-start" spacing={3}>
              <Box
                sx={{
                  width: 64,
                  height: 64,
                  borderRadius: 3,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  color: "#fff",
                  flexShrink: 0,
                  animation: `${float} 4s ease-in-out infinite`,
                }}
              >
                <ShieldIcon />
              </Box>
              <Box sx={{ flexGrow: 1 }}>
                <Typography 
                  variant="h4" 
                  fontWeight={700} 
                  sx={{
                    background: `linear-gradient(135deg, ${theme.palette.text.primary} 0%, ${alpha(theme.palette.text.primary, 0.8)} 100%)`,
                    backgroundClip: "text",
                    WebkitBackgroundClip: "text",
                    mb: 1,
                  }}
                >
                  {projectQuery.data.name}
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                  {projectQuery.data.description || "No description provided"}
                </Typography>
                {projectQuery.data.git_url && (
                  <Chip
                    icon={<GitIcon />}
                    label={projectQuery.data.git_url}
                    variant="outlined"
                    size="small"
                    sx={{ 
                      background: alpha(theme.palette.background.paper, 0.5),
                      backdropFilter: "blur(10px)",
                    }}
                  />
                )}
              </Box>
            </Stack>
          </CardContent>
        </Card>
      )}

      {/* Actions Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Code Source Section */}
        <Grid item xs={12} lg={7}>
          <CodeSourceCard 
            projectId={id}
            onSuccess={() => queryClient.invalidateQueries({ queryKey: ["project", id] })}
          />
        </Grid>

        {/* Scan Section */}
        <Grid item xs={12} lg={5}>
          <Card 
            sx={{ 
              height: "100%",
              background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              transition: "all 0.3s ease",
              "&:hover": {
                border: `1px solid ${alpha(theme.palette.secondary.main, 0.3)}`,
                boxShadow: `0 8px 32px ${alpha(theme.palette.secondary.main, 0.15)}`,
              },
            }}
          >
            <CardContent sx={{ p: 3 }}>
              <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 3 }}>
                <Box
                  sx={{
                    width: 48,
                    height: 48,
                    borderRadius: 2,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    background: `linear-gradient(135deg, ${alpha(theme.palette.secondary.main, 0.2)} 0%, ${alpha(theme.palette.primary.main, 0.2)} 100%)`,
                    color: theme.palette.secondary.main,
                  }}
                >
                  <ScanIcon />
                </Box>
                <Box>
                  <Typography variant="h6" fontWeight={700}>
                    Security Scan
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Run AI-powered vulnerability analysis
                  </Typography>
                </Box>
              </Stack>

              <Button
                variant="contained"
                startIcon={<ScanIcon />}
                onClick={() => scanMutation.mutate()}
                disabled={scanMutation.isPending || activeScanId !== null}
                fullWidth
                sx={{
                  py: 2,
                  fontSize: "1rem",
                  fontWeight: 600,
                  background: activeScanId 
                    ? alpha(theme.palette.warning.main, 0.2)
                    : `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  color: activeScanId ? theme.palette.warning.main : "#fff",
                  boxShadow: activeScanId 
                    ? "none"
                    : `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
                  animation: activeScanId ? `${pulse} 2s ease-in-out infinite` : "none",
                  transition: "all 0.3s ease",
                  "&:hover:not(:disabled)": {
                    background: `linear-gradient(135deg, ${theme.palette.primary.light} 0%, ${theme.palette.secondary.light} 100%)`,
                    boxShadow: `0 6px 30px ${alpha(theme.palette.primary.main, 0.5)}`,
                    transform: "translateY(-2px)",
                  },
                  "&:active:not(:disabled)": {
                    transform: "translateY(0)",
                  },
                }}
              >
                {scanMutation.isPending 
                  ? "🚀 Starting scan..." 
                  : activeScanId 
                    ? "⚡ Scan in progress..." 
                    : "🔍 Start New Scan"}
              </Button>

              {scanMutation.isError && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {(scanMutation.error as Error).message}
                </Alert>
              )}

              {activeScanId && (
                <Box sx={{ mt: 3 }}>
                  <ScanProgress 
                    scanRunId={activeScanId} 
                    onComplete={handleScanComplete}
                  />
                </Box>
              )}

              {!activeScanId && !scanMutation.isPending && (
                <Box 
                  sx={{ 
                    mt: 3, 
                    p: 2, 
                    borderRadius: 2,
                    background: alpha(theme.palette.info.main, 0.05),
                    border: `1px solid ${alpha(theme.palette.info.main, 0.1)}`,
                  }}
                >
                  <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
                    💡 Tip: Upload code or clone a repository first, then run a scan to detect vulnerabilities.
                  </Typography>
                  <Chip
                    icon={<MenuBookIcon sx={{ fontSize: 16 }} />}
                    label="Learn how scanning works →"
                    size="small"
                    clickable
                    onClick={() => navigate("/learn/scanning")}
                    sx={{
                      background: `linear-gradient(135deg, ${alpha("#6366f1", 0.15)}, ${alpha("#8b5cf6", 0.1)})`,
                      border: `1px solid ${alpha("#8b5cf6", 0.25)}`,
                      color: "#a78bfa",
                      fontWeight: 500,
                      fontSize: "0.7rem",
                      "&:hover": {
                        background: `linear-gradient(135deg, ${alpha("#6366f1", 0.25)}, ${alpha("#8b5cf6", 0.2)})`,
                      },
                    }}
                  />
                </Box>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Reports Section */}
      <Box sx={{ mb: 2 }}>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 3 }}>
          <Box
            sx={{
              width: 48,
              height: 48,
              borderRadius: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              color: theme.palette.primary.main,
            }}
          >
            <ReportIcon />
          </Box>
          <Box>
            <Typography variant="h5" fontWeight={700}>
              Scan Reports
            </Typography>
            <Typography variant="body2" color="text.secondary">
              View historical vulnerability analysis results
            </Typography>
          </Box>
        </Stack>

        {reportsQuery.isLoading && (
          <Paper sx={{ p: 3 }}>
            <Skeleton variant="rectangular" height={200} />
          </Paper>
        )}

        {reportsQuery.isError && (
          <Alert severity="error">{(reportsQuery.error as Error).message}</Alert>
        )}

        {reportsQuery.data && reportsQuery.data.length === 0 && (
          <Paper
            sx={{
              p: 6,
              textAlign: "center",
              background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.05)} 0%, ${alpha(theme.palette.primary.main, 0.03)} 100%)`,
              border: `2px dashed ${alpha(theme.palette.info.main, 0.3)}`,
              borderRadius: 3,
            }}
          >
            <Box
              sx={{
                width: 80,
                height: 80,
                borderRadius: "50%",
                bgcolor: alpha(theme.palette.info.main, 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                mx: "auto",
                mb: 3,
                color: theme.palette.info.main,
              }}
            >
              <ReportIcon />
            </Box>
            <Typography variant="h6" gutterBottom fontWeight={600}>
              No reports yet
            </Typography>
            <Typography color="text.secondary" sx={{ maxWidth: 400, mx: "auto", mb: 2 }}>
              Upload code and run a scan to generate your first vulnerability report.
            </Typography>
            <Chip
              icon={<MenuBookIcon sx={{ fontSize: 16 }} />}
              label="📚 Learn about VRAgent's scanning capabilities"
              size="small"
              clickable
              onClick={() => navigate("/learn")}
              sx={{
                background: `linear-gradient(135deg, ${alpha("#6366f1", 0.12)}, ${alpha("#8b5cf6", 0.08)})`,
                border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                color: "#a78bfa",
                fontWeight: 500,
                fontSize: "0.75rem",
                py: 2,
                "&:hover": {
                  background: `linear-gradient(135deg, ${alpha("#6366f1", 0.2)}, ${alpha("#8b5cf6", 0.15)})`,
                  boxShadow: `0 2px 12px ${alpha("#8b5cf6", 0.2)}`,
                },
              }}
            />
          </Paper>
        )}

        {reportsQuery.data && reportsQuery.data.length > 0 && (
          <TableContainer 
            component={Paper}
            sx={{
              background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              borderRadius: 3,
              overflow: "hidden",
            }}
          >
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Date</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Risk Score</TableCell>
                  <TableCell sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Vulnerabilities</TableCell>
                  <TableCell align="right" sx={{ fontWeight: 700, fontSize: "0.85rem" }}>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {reportsQuery.data.map((r, index) => {
                  const counts = (r.data?.severity_counts || {}) as Record<string, number>;
                  const critical = counts["critical"] || 0;
                  const high = counts["high"] || 0;
                  const medium = counts["medium"] || 0;
                  const low = counts["low"] || 0;
                  const riskScore = r.overall_risk_score;

                  return (
                    <TableRow
                      key={r.id}
                      sx={{
                        transition: "all 0.2s ease",
                        "&:hover": { 
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                          "& .view-btn": {
                            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                            color: "#fff",
                            borderColor: "transparent",
                          },
                        },
                        cursor: "pointer",
                        animation: `fadeIn 0.3s ease ${index * 0.05}s both`,
                        "@keyframes fadeIn": {
                          from: { opacity: 0, transform: "translateY(10px)" },
                          to: { opacity: 1, transform: "translateY(0)" },
                        },
                      }}
                      onClick={() => navigate(`/reports/${r.id}`)}
                    >
                      <TableCell>
                        <Typography variant="body2" fontWeight={600}>
                          {new Date(r.created_at).toLocaleDateString()}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(r.created_at).toLocaleTimeString()}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1.5 }}>
                          <Box
                            sx={{
                              width: 40,
                              height: 40,
                              borderRadius: 2,
                              display: "flex",
                              alignItems: "center",
                              justifyContent: "center",
                              background: alpha(getRiskColor(riskScore, theme), 0.15),
                              color: getRiskColor(riskScore, theme),
                              fontWeight: 700,
                              fontSize: "0.9rem",
                              boxShadow: `0 0 15px ${alpha(getRiskColor(riskScore, theme), 0.3)}`,
                            }}
                          >
                            {riskScore != null ? Math.round(riskScore) : "N/A"}
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={0.5} flexWrap="wrap" gap={0.5}>
                          {critical > 0 && (
                            <Chip
                              label={`${critical} Critical`}
                              size="small"
                              sx={{
                                bgcolor: getSeverityColor("critical", theme).bg,
                                color: getSeverityColor("critical", theme).text,
                                fontWeight: 600,
                                fontSize: "0.7rem",
                                boxShadow: `0 0 10px ${getSeverityColor("critical", theme).glow}`,
                              }}
                            />
                          )}
                          {high > 0 && (
                            <Chip
                              label={`${high} High`}
                              size="small"
                              sx={{
                                bgcolor: getSeverityColor("high", theme).bg,
                                color: getSeverityColor("high", theme).text,
                                fontWeight: 600,
                                fontSize: "0.7rem",
                              }}
                            />
                          )}
                          {medium > 0 && (
                            <Chip
                              label={`${medium} Med`}
                              size="small"
                              sx={{
                                bgcolor: getSeverityColor("medium", theme).bg,
                                color: getSeverityColor("medium", theme).text,
                                fontWeight: 600,
                                fontSize: "0.7rem",
                              }}
                            />
                          )}
                          {low > 0 && (
                            <Chip
                              label={`${low} Low`}
                              size="small"
                              sx={{
                                bgcolor: getSeverityColor("low", theme).bg,
                                color: getSeverityColor("low", theme).text,
                                fontWeight: 600,
                                fontSize: "0.7rem",
                              }}
                            />
                          )}
                          {critical === 0 && high === 0 && medium === 0 && low === 0 && (
                            <Chip
                              label="✓ Clean"
                              size="small"
                              sx={{
                                bgcolor: alpha(theme.palette.success.main, 0.15),
                                color: theme.palette.success.main,
                                fontWeight: 600,
                                fontSize: "0.7rem",
                              }}
                            />
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell align="right">
                        <Stack direction="row" spacing={1} justifyContent="flex-end">
                          <Button
                            className="view-btn"
                            component={Link}
                            to={`/reports/${r.id}`}
                            variant="outlined"
                            size="small"
                            endIcon={<ArrowRightIcon />}
                            onClick={(e) => e.stopPropagation()}
                            sx={{
                              fontWeight: 600,
                              transition: "all 0.3s ease",
                            }}
                          >
                            View Report
                          </Button>
                          <Tooltip title="Delete Report">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleDeleteClick(r.id, new Date(r.created_at).toLocaleDateString("en-US", {
                                  month: "short",
                                  day: "numeric",
                                  year: "numeric",
                                }));
                              }}
                              sx={{
                                color: theme.palette.error.main,
                                opacity: 0.7,
                                transition: "all 0.2s ease",
                                "&:hover": {
                                  opacity: 1,
                                  bgcolor: alpha(theme.palette.error.main, 0.1),
                                },
                              }}
                            >
                              <DeleteIcon />
                            </IconButton>
                          </Tooltip>
                        </Stack>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Delete Confirmation Dialog */}
        <Dialog
          open={deleteDialogOpen}
          onClose={handleDeleteCancel}
          PaperProps={{
            sx: {
              background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.paper, 0.9)} 100%)`,
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            },
          }}
        >
          <DialogTitle sx={{ fontWeight: 700 }}>Delete Report</DialogTitle>
          <DialogContent>
            <DialogContentText>
              Are you sure you want to delete the report from{" "}
              <strong>{reportToDelete?.date}</strong>? This will permanently remove
              all findings and exploit scenarios associated with this report.
            </DialogContentText>
          </DialogContent>
          <DialogActions sx={{ px: 3, pb: 2 }}>
            <Button onClick={handleDeleteCancel} color="inherit">
              Cancel
            </Button>
            <Button
              onClick={handleDeleteConfirm}
              color="error"
              variant="contained"
              disabled={deleteReportMutation.isPending}
              sx={{
                fontWeight: 600,
                "&:hover": {
                  boxShadow: `0 4px 20px ${alpha(theme.palette.error.main, 0.4)}`,
                },
              }}
            >
              {deleteReportMutation.isPending ? "Deleting..." : "Delete"}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Scan Complete Snackbar */}
        <Snackbar
          open={scanCompleteSnackbar}
          autoHideDuration={6000}
          onClose={() => setScanCompleteSnackbar(false)}
          anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
          TransitionComponent={(props: SlideProps) => <Slide {...props} direction="up" />}
        >
          <Alert
            onClose={() => setScanCompleteSnackbar(false)}
            severity="success"
            variant="filled"
            sx={{
              width: "100%",
              fontWeight: 600,
              fontSize: "1rem",
              background: `linear-gradient(135deg, ${theme.palette.success.main} 0%, ${theme.palette.success.dark} 100%)`,
              boxShadow: `0 8px 32px ${alpha(theme.palette.success.main, 0.4)}`,
              "& .MuiAlert-icon": {
                fontSize: "1.5rem",
              },
            }}
          >
            🎉 Security Scan Complete! Your report is ready to view.
          </Alert>
        </Snackbar>
      </Box>
    </Box>
  );
}
