import React, { useState, useRef, useCallback } from "react";
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  alpha,
  useTheme,
  Chip,
  Tabs,
  Tab,
  Stack,
  IconButton,
  Skeleton,
  Tooltip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Alert,
  FormControlLabel,
  Switch,
  TextField,
  InputAdornment,
  Collapse,
  LinearProgress,
} from "@mui/material";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, QuickScanResponse } from "../api/client";
import SecurityIcon from "@mui/icons-material/Security";
import ScanIcon from "@mui/icons-material/Radar";
import UploadIcon from "@mui/icons-material/CloudUpload";
import CloneIcon from "@mui/icons-material/GitHub";
import ReportIcon from "@mui/icons-material/Assessment";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import PsychologyIcon from "@mui/icons-material/Psychology";
import ArrowRightIcon from "@mui/icons-material/ArrowForward";
import ShareIcon from "@mui/icons-material/Share";
import DeleteIcon from "@mui/icons-material/Delete";
import FolderIcon from "@mui/icons-material/Folder";
import ScanProgress from "../components/ScanProgress";
import JSZip from "jszip";
import { keyframes } from "@mui/system";

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.7; }
`;

const float = keyframes`
  0%, 100% { transform: translateY(0px); }
  50% { transform: translateY(-10px); }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

const glow = keyframes`
  0%, 100% { box-shadow: 0 0 20px rgba(99, 102, 241, 0.3); }
  50% { box-shadow: 0 0 40px rgba(99, 102, 241, 0.6), 0 0 60px rgba(34, 211, 238, 0.3); }
`;

const slideIn = keyframes`
  from { opacity: 0; transform: translateY(-10px); }
  to { opacity: 1; transform: translateY(0); }
`;

// Helper functions
function getRiskColor(score: number | null | undefined, theme: any): string {
  if (score == null) return theme.palette.text.secondary;
  if (score >= 80) return theme.palette.error.main;
  if (score >= 60) return "#f97316";
  if (score >= 40) return theme.palette.warning.main;
  if (score >= 20) return "#22c55e";
  return theme.palette.success.main;
}

function getSeverityColor(severity: string, theme: any): { bg: string; text: string; glow: string } {
  switch (severity.toLowerCase()) {
    case "critical":
      return { bg: alpha("#dc2626", 0.15), text: "#ef4444", glow: alpha("#dc2626", 0.4) };
    case "high":
      return { bg: alpha("#f97316", 0.15), text: "#fb923c", glow: alpha("#f97316", 0.3) };
    case "medium":
      return { bg: alpha("#eab308", 0.15), text: "#facc15", glow: alpha("#eab308", 0.2) };
    case "low":
      return { bg: alpha("#22c55e", 0.15), text: "#4ade80", glow: alpha("#22c55e", 0.2) };
    default:
      return { bg: alpha(theme.palette.grey[500], 0.15), text: theme.palette.grey[400], glow: "transparent" };
  }
}

const StaticAnalysisHub: React.FC = () => {
  const theme = useTheme();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  
  const [activeTab, setActiveTab] = useState(0);
  const [enhancedScan, setEnhancedScan] = useState(false);
  const [activeScanId, setActiveScanId] = useState<number | null>(null);
  const [activeProjectId, setActiveProjectId] = useState<number | null>(null);
  
  // Upload state
  const [isDragOver, setIsDragOver] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[] | null>(null);
  const [uploadMode, setUploadMode] = useState<"zip" | "folder">("folder");
  const [processingStatus, setProcessingStatus] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);
  
  // Clone state
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  // Fetch recent reports across all projects
  const reportsQuery = useQuery({
    queryKey: ["recentReports"],
    queryFn: () => api.getRecentReports(20),
  });

  // Quick scan upload mutation
  const uploadMutation = useMutation({
    mutationFn: async (file: File) => {
      return api.quickScanUpload(file, enhancedScan);
    },
    onSuccess: (data: QuickScanResponse) => {
      setActiveScanId(data.scan_run_id);
      setActiveProjectId(data.project_id);
      setSelectedFiles(null);
      setProcessingStatus("");
    },
  });

  // Quick scan clone mutation
  const cloneMutation = useMutation({
    mutationFn: async () => {
      return api.quickScanClone(repoUrl.trim(), branch.trim() || undefined, enhancedScan);
    },
    onSuccess: (data: QuickScanResponse) => {
      setActiveScanId(data.scan_run_id);
      setActiveProjectId(data.project_id);
      setRepoUrl("");
      setBranch("");
    },
  });

  const handleScanComplete = () => {
    setActiveScanId(null);
    setActiveProjectId(null);
    queryClient.invalidateQueries({ queryKey: ["recentReports"] });
  };

  // File handling
  const processAndUpload = async (files: File[]) => {
    if (uploadMode === "zip" && files.length === 1 && files[0].name.endsWith(".zip")) {
      uploadMutation.mutate(files[0]);
    } else {
      setProcessingStatus("Creating archive...");
      const zip = new JSZip();
      
      for (const file of files) {
        const relativePath = (file as any).webkitRelativePath || file.name;
        const arrayBuffer = await file.arrayBuffer();
        zip.file(relativePath, arrayBuffer);
        setProcessingStatus(`Adding: ${relativePath.split('/').pop()}`);
      }

      setProcessingStatus("Compressing...");
      const zipBlob = await zip.generateAsync({ 
        type: "blob",
        compression: "DEFLATE",
        compressionOptions: { level: 6 }
      }, (metadata) => {
        setProcessingStatus(`Compressing: ${Math.round(metadata.percent)}%`);
      });
      
      const folderName = files[0] && (files[0] as any).webkitRelativePath 
        ? (files[0] as any).webkitRelativePath.split('/')[0] 
        : "upload";
      const zipFile = new File([zipBlob], `${folderName}.zip`, { type: "application/zip" });
      setProcessingStatus("Uploading & starting scan...");
      uploadMutation.mutate(zipFile);
    }
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);

    const items = e.dataTransfer.items;
    const files: File[] = [];

    if (items) {
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === "file") {
          const file = item.getAsFile();
          if (file) files.push(file);
        }
      }
    }

    if (files.length > 0) {
      if (uploadMode === "zip" && (!files[0].name.endsWith(".zip") || files.length > 1)) {
        setUploadMode("folder");
      }
      setSelectedFiles(files);
    }
  }, [uploadMode]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      setSelectedFiles(Array.from(files));
    }
  };

  const handleUploadAndScan = () => {
    if (selectedFiles && selectedFiles.length > 0) {
      processAndUpload(selectedFiles);
    }
  };

  const handleCloneAndScan = (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;
    cloneMutation.mutate();
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const getTotalSize = () => {
    if (!selectedFiles) return 0;
    return selectedFiles.reduce((acc, f) => acc + f.size, 0);
  };

  const getPlatformInfo = () => {
    if (repoUrl.includes("github.com")) return { name: "GitHub", color: "#333" };
    if (repoUrl.includes("gitlab.com")) return { name: "GitLab", color: "#FC6D26" };
    if (repoUrl.includes("bitbucket.org")) return { name: "Bitbucket", color: "#0052CC" };
    if (repoUrl.includes("dev.azure.com")) return { name: "Azure DevOps", color: "#0078D7" };
    return null;
  };

  const platform = getPlatformInfo();
  const isScanning = activeScanId !== null || uploadMutation.isPending || cloneMutation.isPending;

  return (
    <Box>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Stack direction="row" alignItems="center" spacing={2}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 3,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              color: theme.palette.primary.main,
            }}
          >
            <SecurityIcon sx={{ fontSize: 32 }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Static Security Scan
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Upload code or clone a repo to instantly scan for vulnerabilities
            </Typography>
          </Box>
        </Stack>
      </Box>

      {/* Active Scan Progress */}
      {activeScanId && (
        <Card 
          sx={{ 
            mb: 4,
            background: `linear-gradient(135deg, ${alpha(theme.palette.warning.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
          }}
        >
          <CardContent sx={{ p: 3 }}>
            <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
              <ScanIcon sx={{ color: theme.palette.warning.main, animation: `${pulse} 2s ease-in-out infinite` }} />
              <Typography variant="h6" fontWeight={600}>
                ⚡ Scan in Progress
              </Typography>
            </Stack>
            <ScanProgress 
              scanRunId={activeScanId} 
              onComplete={handleScanComplete}
            />
            {activeProjectId && (
              <Button
                component={Link}
                to={`/projects/${activeProjectId}`}
                size="small"
                sx={{ mt: 2 }}
              >
                View Project →
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Main Content Grid */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {/* Code Source Section */}
        <Grid item xs={12} lg={7}>
          <Card 
            sx={{ 
              height: "100%",
              background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
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
                    }
                  }}
                >
                  <Tab icon={<UploadIcon />} iconPosition="start" label="Upload Code" />
                  <Tab icon={<CloneIcon />} iconPosition="start" label="Clone Repo" />
                </Tabs>
              </Box>
              
              <Box sx={{ p: 3, flexGrow: 1 }}>
                {activeTab === 0 && (
                  <Box>
                    {/* Mode Selector */}
                    <Box
                      sx={{
                        mb: 3,
                        p: 0.5,
                        borderRadius: 2,
                        background: alpha(theme.palette.background.paper, 0.5),
                        border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                      }}
                    >
                      <Tabs
                        value={uploadMode}
                        onChange={(_, v) => {
                          setUploadMode(v);
                          setSelectedFiles(null);
                        }}
                        variant="fullWidth"
                        sx={{
                          minHeight: 40,
                          "& .MuiTabs-indicator": {
                            height: "100%",
                            borderRadius: 1.5,
                            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
                            zIndex: 0,
                          },
                          "& .MuiTab-root": {
                            minHeight: 40,
                            zIndex: 1,
                            fontWeight: 600,
                            fontSize: "0.85rem",
                          },
                        }}
                      >
                        <Tab value="folder" label="📁 Folder" sx={{ borderRadius: 1.5 }} />
                        <Tab value="zip" label="📦 ZIP File" sx={{ borderRadius: 1.5 }} />
                      </Tabs>
                    </Box>

                    {/* Hidden inputs */}
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".zip"
                      hidden
                      onChange={handleFileSelect}
                    />
                    <input
                      ref={folderInputRef}
                      type="file"
                      // @ts-ignore
                      webkitdirectory=""
                      directory=""
                      multiple
                      hidden
                      onChange={handleFileSelect}
                    />

                    {/* Drop Zone */}
                    <Box
                      onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                      onDragLeave={() => setIsDragOver(false)}
                      onDrop={handleDrop}
                      onClick={() => {
                        if (uploadMode === "zip") {
                          fileInputRef.current?.click();
                        } else {
                          folderInputRef.current?.click();
                        }
                      }}
                      sx={{
                        p: 4,
                        borderRadius: 3,
                        cursor: "pointer",
                        transition: "all 0.4s cubic-bezier(0.4, 0, 0.2, 1)",
                        background: isDragOver
                          ? `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)} 0%, ${alpha(theme.palette.secondary.main, 0.15)} 100%)`
                          : `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.8)} 0%, ${alpha(theme.palette.background.paper, 0.6)} 100%)`,
                        border: `2px dashed ${isDragOver ? theme.palette.primary.main : alpha(theme.palette.divider, 0.3)}`,
                        animation: isDragOver ? `${glow} 2s ease-in-out infinite` : "none",
                        "&:hover": {
                          borderColor: theme.palette.primary.main,
                          "& .upload-icon": {
                            animation: `${float} 2s ease-in-out infinite`,
                          },
                        },
                      }}
                    >
                      <Box sx={{ textAlign: "center" }}>
                        <Box
                          className="upload-icon"
                          sx={{
                            display: "inline-flex",
                            alignItems: "center",
                            justifyContent: "center",
                            width: 80,
                            height: 80,
                            borderRadius: "50%",
                            mb: 2,
                            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
                            color: theme.palette.primary.main,
                          }}
                        >
                          {uploadMode === "zip" ? <UploadIcon sx={{ fontSize: 40 }} /> : <FolderIcon sx={{ fontSize: 40 }} />}
                        </Box>
                        
                        <Typography 
                          variant="h6" 
                          fontWeight={600} 
                          sx={{
                            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                            backgroundClip: "text",
                            WebkitBackgroundClip: "text",
                            WebkitTextFillColor: "transparent",
                            mb: 1,
                          }}
                        >
                          {isDragOver 
                            ? "Drop it like it's hot! 🔥"
                            : uploadMode === "zip" 
                              ? "Drop a ZIP file here"
                              : "Drop a folder here"}
                        </Typography>
                        
                        <Typography variant="body2" color="text.secondary">
                          or click to {uploadMode === "zip" ? "select a ZIP file" : "select a folder"}
                        </Typography>
                      </Box>
                    </Box>

                    {/* Selected Files */}
                    {selectedFiles && selectedFiles.length > 0 && (
                      <Box
                        sx={{
                          mt: 3,
                          p: 2,
                          borderRadius: 2,
                          background: `linear-gradient(135deg, ${alpha(theme.palette.success.main, 0.1)} 0%, ${alpha(theme.palette.primary.main, 0.05)} 100%)`,
                          border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
                        }}
                      >
                        <Typography variant="subtitle2" fontWeight={600}>
                          {(() => {
                            const firstFile = selectedFiles[0] as any;
                            if (firstFile.webkitRelativePath) {
                              const folderName = firstFile.webkitRelativePath.split('/')[0];
                              return `📁 ${folderName} (${selectedFiles.length} files)`;
                            }
                            if (selectedFiles.length === 1) {
                              return `📦 ${selectedFiles[0].name}`;
                            }
                            return `${selectedFiles.length} files selected`;
                          })()}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Total size: {formatSize(getTotalSize())}
                        </Typography>
                      </Box>
                    )}

                    {/* Progress */}
                    {(uploadMutation.isPending || processingStatus) && (
                      <Box sx={{ mt: 3 }}>
                        <Typography variant="caption" sx={{ animation: `${pulse} 1.5s ease-in-out infinite` }}>
                          {processingStatus || "Uploading..."}
                        </Typography>
                        <LinearProgress sx={{ mt: 1, borderRadius: 2 }} />
                      </Box>
                    )}

                    {/* Upload & Scan Button */}
                    {selectedFiles && selectedFiles.length > 0 && !uploadMutation.isPending && !activeScanId && (
                      <Button
                        variant="contained"
                        fullWidth
                        onClick={handleUploadAndScan}
                        startIcon={<ScanIcon />}
                        sx={{
                          mt: 3,
                          py: 1.5,
                          fontWeight: 600,
                          background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                          boxShadow: `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`,
                        }}
                      >
                        🚀 Upload & Start Scan
                      </Button>
                    )}

                    {uploadMutation.isError && (
                      <Alert severity="error" sx={{ mt: 2 }}>
                        {(uploadMutation.error as Error).message}
                      </Alert>
                    )}
                  </Box>
                )}

                {activeTab === 1 && (
                  <Box component="form" onSubmit={handleCloneAndScan}>
                    <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mb: 2 }}>
                      {["GitHub", "GitLab", "Bitbucket", "Azure"].map((p) => (
                        <Chip
                          key={p}
                          label={p}
                          size="small"
                          sx={{
                            background: alpha(theme.palette.primary.main, 0.1),
                            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                            fontWeight: 500,
                          }}
                        />
                      ))}
                    </Stack>

                    <TextField
                      placeholder="https://github.com/owner/repository"
                      value={repoUrl}
                      onChange={(e) => setRepoUrl(e.target.value)}
                      fullWidth
                      disabled={cloneMutation.isPending || !!activeScanId}
                      InputProps={{
                        startAdornment: (
                          <InputAdornment position="start">
                            <CloneIcon sx={{ color: platform ? platform.color : "text.secondary" }} />
                          </InputAdornment>
                        ),
                        endAdornment: platform && (
                          <InputAdornment position="end">
                            <Chip label={platform.name} size="small" sx={{ animation: `${slideIn} 0.3s ease` }} />
                          </InputAdornment>
                        ),
                      }}
                      sx={{ mb: 2 }}
                    />

                    <Button
                      size="small"
                      onClick={() => setShowAdvanced(!showAdvanced)}
                      sx={{ mb: 2, textTransform: "none", color: "text.secondary" }}
                    >
                      {showAdvanced ? "Hide" : "Show"} branch options
                    </Button>
                    
                    <Collapse in={showAdvanced}>
                      <TextField
                        label="Branch"
                        placeholder="main"
                        value={branch}
                        onChange={(e) => setBranch(e.target.value)}
                        fullWidth
                        size="small"
                        helperText="Leave empty to use the default branch"
                        sx={{ mb: 2 }}
                      />
                    </Collapse>

                    {cloneMutation.isPending && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="caption" sx={{ animation: `${pulse} 1.5s ease-in-out infinite` }}>
                          🔄 Cloning repository & starting scan...
                        </Typography>
                        <LinearProgress sx={{ mt: 1, borderRadius: 2 }} />
                      </Box>
                    )}

                    {cloneMutation.isError && (
                      <Alert severity="error" sx={{ mb: 2 }}>
                        {(cloneMutation.error as Error).message}
                      </Alert>
                    )}

                    <Button
                      type="submit"
                      variant="contained"
                      fullWidth
                      disabled={cloneMutation.isPending || !repoUrl.trim() || !!activeScanId}
                      startIcon={<ScanIcon />}
                      sx={{
                        py: 1.5,
                        fontWeight: 600,
                        background: repoUrl.trim()
                          ? `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`
                          : undefined,
                        boxShadow: repoUrl.trim()
                          ? `0 4px 20px ${alpha(theme.palette.primary.main, 0.4)}`
                          : "none",
                      }}
                    >
                      🚀 Clone & Start Scan
                    </Button>

                    <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 2, textAlign: "center" }}>
                      🔓 Only public repositories are currently supported
                    </Typography>
                  </Box>
                )}
              </Box>
            </CardContent>
          </Card>
        </Grid>

        {/* Scan Options Section */}
        <Grid item xs={12} lg={5}>
          <Card 
            sx={{ 
              height: "100%",
              background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.9)} 0%, ${alpha(theme.palette.background.paper, 0.7)} 100%)`,
              backdropFilter: "blur(20px)",
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
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
                    Scan Options
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Configure your security scan
                  </Typography>
                </Box>
              </Stack>

              {/* AI-Guided Deep Analysis info */}
              <Box
                sx={{
                  p: 2,
                  borderRadius: 2,
                  background: alpha("#8b5cf6", 0.08),
                  border: `1px solid ${alpha("#8b5cf6", 0.2)}`,
                  mb: 2,
                }}
              >
                <Stack direction="row" alignItems="center" spacing={1}>
                  <PsychologyIcon sx={{ color: "#8b5cf6", fontSize: 20 }} />
                  <Box>
                    <Typography variant="body2" fontWeight={600} color="#8b5cf6">
                      AI-Guided Deep Analysis Included
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Multi-pass AI code analysis with CVE + SAST context
                    </Typography>
                  </Box>
                </Stack>
              </Box>

              {/* Enhanced Scan Toggle */}
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 2,
                  background: enhancedScan 
                    ? alpha("#f59e0b", 0.1) 
                    : alpha(theme.palette.action.hover, 0.3),
                  border: `1px solid ${enhancedScan ? alpha("#f59e0b", 0.3) : alpha(theme.palette.divider, 0.3)}`,
                  mb: 3,
                }}
              >
                <FormControlLabel
                  control={
                    <Switch
                      size="small"
                      checked={enhancedScan}
                      onChange={(e) => setEnhancedScan(e.target.checked)}
                      disabled={isScanning}
                      sx={{
                        "& .MuiSwitch-switchBase.Mui-checked": { color: "#f59e0b" },
                        "& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track": { backgroundColor: "#f59e0b" },
                      }}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="caption" fontWeight={600} color={enhancedScan ? "#f59e0b" : "text.secondary"}>
                        Enhanced Scan {enhancedScan && "✓"}
                      </Typography>
                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", fontSize: "0.65rem" }}>
                        {enhancedScan 
                          ? "More files analyzed with deeper inspection per pass" 
                          : "Standard multi-pass analysis"}
                      </Typography>
                    </Box>
                  }
                  sx={{ m: 0 }}
                />
              </Box>

              {/* Tip */}
              <Box 
                sx={{ 
                  p: 2, 
                  borderRadius: 2,
                  background: alpha(theme.palette.info.main, 0.05),
                  border: `1px solid ${alpha(theme.palette.info.main, 0.1)}`,
                }}
              >
                <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1.5 }}>
                  💡 Upload or clone your code, then a scan will start automatically. Results will appear below and a project will be created for you.
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
                  }}
                />
              </Box>

              {/* Link to Projects */}
              <Box sx={{ mt: 3, pt: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                <Typography variant="caption" color="text.secondary" gutterBottom sx={{ display: "block" }}>
                  Want more control over your scans?
                </Typography>
                <Button
                  component={Link}
                  to="/projects"
                  size="small"
                  sx={{ textTransform: "none" }}
                >
                  📁 Go to Projects →
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Reports Section */}
      <Box>
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
              Recent Scan Reports
            </Typography>
            <Typography variant="body2" color="text.secondary">
              View your latest vulnerability analysis results
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
              <ReportIcon sx={{ fontSize: 40 }} />
            </Box>
            <Typography variant="h6" gutterBottom fontWeight={600}>
              No reports yet
            </Typography>
            <Typography color="text.secondary" sx={{ maxWidth: 400, mx: "auto" }}>
              Upload code or clone a repository above to generate your first vulnerability report.
            </Typography>
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
            }}
          >
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>Date</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Project</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Risk Score</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Vulnerabilities</TableCell>
                  <TableCell align="right" sx={{ fontWeight: 700 }}>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {reportsQuery.data.map((r, index) => {
                  const counts = r.severity_counts || {};
                  const critical = counts["critical"] || 0;
                  const high = counts["high"] || 0;
                  const medium = counts["medium"] || 0;
                  const low = counts["low"] || 0;
                  const riskScore = r.overall_risk_score;

                  return (
                    <TableRow
                      key={r.id}
                      sx={{
                        cursor: "pointer",
                        "&:hover": { 
                          bgcolor: alpha(theme.palette.primary.main, 0.05),
                          "& .view-btn": {
                            background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                            color: "#fff",
                          },
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
                        <Typography variant="body2" fontWeight={500}>
                          {r.project_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
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
                            boxShadow: `0 0 15px ${alpha(getRiskColor(riskScore, theme), 0.3)}`,
                          }}
                        >
                          {riskScore != null ? Math.round(riskScore) : "N/A"}
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
                          >
                            View
                          </Button>
                          <Tooltip title="View Project">
                            <IconButton
                              size="small"
                              component={Link}
                              to={`/projects/${r.project_id}`}
                              onClick={(e) => e.stopPropagation()}
                              sx={{ color: theme.palette.primary.main, opacity: 0.7 }}
                            >
                              <FolderIcon fontSize="small" />
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
      </Box>
    </Box>
  );
};

export default StaticAnalysisHub;
