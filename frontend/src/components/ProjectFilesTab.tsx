import { useState, useRef, useCallback, useEffect } from "react";
import {
  Box,
  Typography,
  Paper,
  Grid,
  Button,
  IconButton,
  Chip,
  Stack,
  CircularProgress,
  Alert,
  Tab,
  Tabs,
  TextField,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Card,
  CardContent,
  Tooltip,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  alpha,
  useTheme,
  Avatar,
  Skeleton,
  Collapse,
  Divider,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  MenuItem,
} from "@mui/material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  apiClient,
  ProjectFile,
  DocumentAnalysisReport,
  ReportChatMessage,
  DocumentTranslation,
} from "../api/client";

// Icons
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import FolderIcon from "@mui/icons-material/Folder";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import DescriptionIcon from "@mui/icons-material/Description";
import SlideshowIcon from "@mui/icons-material/Slideshow";
import ImageIcon from "@mui/icons-material/Image";
import CodeIcon from "@mui/icons-material/Code";
import TextSnippetIcon from "@mui/icons-material/TextSnippet";
import DeleteIcon from "@mui/icons-material/Delete";
import DownloadIcon from "@mui/icons-material/Download";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import ChatIcon from "@mui/icons-material/Chat";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import HourglassEmptyIcon from "@mui/icons-material/HourglassEmpty";
import RefreshIcon from "@mui/icons-material/Refresh";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import SendIcon from "@mui/icons-material/Send";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import ArticleIcon from "@mui/icons-material/Article";
import DeleteSweepIcon from "@mui/icons-material/DeleteSweep";
import AttachFileIcon from "@mui/icons-material/AttachFile";
import TuneIcon from "@mui/icons-material/Tune";
import FileCopyIcon from "@mui/icons-material/FileCopy";
import TranslateIcon from "@mui/icons-material/Translate";

interface ProjectFilesTabProps {
  projectId: number;
  projectName: string;
  canEdit: boolean;
}

// Helper functions
const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
};

const getFileIcon = (mimeType: string | null, filename: string) => {
  if (!mimeType) {
    const ext = filename.split(".").pop()?.toLowerCase();
    if (["pdf"].includes(ext || "")) return <PictureAsPdfIcon />;
    if (["doc", "docx"].includes(ext || "")) return <DescriptionIcon />;
    if (["ppt", "pptx"].includes(ext || "")) return <SlideshowIcon />;
    if (["jpg", "jpeg", "png", "gif", "webp"].includes(ext || "")) return <ImageIcon />;
    if (["js", "ts", "py", "java", "cpp", "c", "go", "rs"].includes(ext || "")) return <CodeIcon />;
    if (["txt", "md"].includes(ext || "")) return <TextSnippetIcon />;
    return <InsertDriveFileIcon />;
  }
  
  if (mimeType.includes("pdf")) return <PictureAsPdfIcon />;
  if (mimeType.includes("word") || mimeType.includes("document")) return <DescriptionIcon />;
  if (mimeType.includes("presentation") || mimeType.includes("powerpoint")) return <SlideshowIcon />;
  if (mimeType.includes("image")) return <ImageIcon />;
  if (mimeType.includes("text")) return <TextSnippetIcon />;
  return <InsertDriveFileIcon />;
};

const getStatusIcon = (status: string) => {
  switch (status) {
    case "completed":
      return <CheckCircleIcon sx={{ color: "success.main" }} />;
    case "failed":
      return <ErrorIcon sx={{ color: "error.main" }} />;
    case "processing":
      return <CircularProgress size={20} />;
    default:
      return <HourglassEmptyIcon sx={{ color: "warning.main" }} />;
  }
};

const getStatusColor = (status: string): "success" | "error" | "warning" | "info" => {
  switch (status) {
    case "completed":
      return "success";
    case "failed":
      return "error";
    case "processing":
      return "info";
    default:
      return "warning";
  }
};

export default function ProjectFilesTab({ projectId, projectName, canEdit }: ProjectFilesTabProps) {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<"files" | "documents" | "translations">("files");
  const [isDragging, setIsDragging] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [selectedReport, setSelectedReport] = useState<DocumentAnalysisReport | null>(null);
  const [chatMessage, setChatMessage] = useState("");
  const [deleteDialog, setDeleteDialog] = useState<{ type: "file" | "report" | "translation"; id: number; name: string } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const documentInputRef = useRef<HTMLInputElement>(null);
  const translationInputRef = useRef<HTMLInputElement>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  
  // New states for multi-file upload
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [customPrompt, setCustomPrompt] = useState("");
  const [showPromptField, setShowPromptField] = useState(false);
  const [analysisDepth, setAnalysisDepth] = useState<"standard" | "deep">("deep");
  const [translationProgress, setTranslationProgress] = useState<number | null>(null);
  const [translationTargetLanguage, setTranslationTargetLanguage] = useState("English");
  const [translationSourceLanguage, setTranslationSourceLanguage] = useState("");
  const [translationOcrLanguages, setTranslationOcrLanguages] = useState("");

  // Queries
  const filesQuery = useQuery<ProjectFile[]>({
    queryKey: ["project-files", projectId],
    queryFn: () => apiClient.getProjectFiles(projectId),
  });

  const reportsQuery = useQuery<DocumentAnalysisReport[]>({
    queryKey: ["project-reports", projectId],
    queryFn: () => apiClient.getAnalysisReports(projectId),
  });

  const translationsQuery = useQuery<DocumentTranslation[]>({
    queryKey: ["project-translations", projectId],
    queryFn: () => apiClient.getDocumentTranslations(projectId),
  });

  // Check if any reports are processing - refetch if so
  const hasProcessingReports = reportsQuery.data?.some(
    (r) => r.status === "pending" || r.status === "processing"
  );

  const hasProcessingTranslations = translationsQuery.data?.some(
    (t) => t.status === "pending" || t.status === "processing"
  );

  // Use effect to trigger refetch while processing
  useEffect(() => {
    if (!hasProcessingReports) return;
    const interval = setInterval(() => {
      reportsQuery.refetch();
    }, 3000);
    return () => clearInterval(interval);
  }, [hasProcessingReports, reportsQuery]);

  useEffect(() => {
    if (!hasProcessingTranslations) return;
    const interval = setInterval(() => {
      translationsQuery.refetch();
    }, 3000);
    return () => clearInterval(interval);
  }, [hasProcessingTranslations, translationsQuery]);

  const chatQuery = useQuery<ReportChatMessage[]>({
    queryKey: ["report-chat", selectedReport?.id],
    queryFn: () => {
      if (!selectedReport) return Promise.resolve([]);
      return apiClient.getReportChat(projectId, selectedReport.id);
    },
    enabled: !!selectedReport && selectedReport.status === "completed",
  });

  // Mutations
  const uploadFileMutation = useMutation({
    mutationFn: async (file: File) => {
      return apiClient.uploadProjectFile(projectId, file, undefined, undefined, (progress) => {
        setUploadProgress(progress);
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-files", projectId] });
      setUploadProgress(null);
    },
    onError: () => {
      setUploadProgress(null);
    },
  });

  const createReportMutation = useMutation({
    mutationFn: async ({ files, prompt, depth }: { files: File[]; prompt: string; depth: string }) => {
      return apiClient.createAnalysisReport(projectId, files, prompt || undefined, depth, (progress) => {
        setUploadProgress(progress);
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-reports", projectId] });
      setUploadProgress(null);
      setSelectedFiles([]);
      setCustomPrompt("");
      setShowPromptField(false);
    },
    onError: () => {
      setUploadProgress(null);
    },
  });

  const deleteFileMutation = useMutation({
    mutationFn: (fileId: number) => apiClient.deleteProjectFile(projectId, fileId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-files", projectId] });
      setDeleteDialog(null);
    },
  });

  const deleteReportMutation = useMutation({
    mutationFn: (reportId: number) => apiClient.deleteAnalysisReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-reports", projectId] });
      setDeleteDialog(null);
      if (selectedReport?.id === deleteDialog?.id) {
        setSelectedReport(null);
      }
    },
  });

  const createTranslationMutation = useMutation({
    mutationFn: async ({ file }: { file: File }) => {
      return apiClient.createDocumentTranslation(
        projectId,
        file,
        {
          targetLanguage: translationTargetLanguage || "English",
          sourceLanguage: translationSourceLanguage || undefined,
          ocrLanguages: translationOcrLanguages || undefined,
        },
        (progress) => setTranslationProgress(progress)
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-translations", projectId] });
      setTranslationProgress(null);
    },
    onError: () => {
      setTranslationProgress(null);
    },
  });

  const deleteTranslationMutation = useMutation({
    mutationFn: (translationId: number) => apiClient.deleteDocumentTranslation(projectId, translationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-translations", projectId] });
      setDeleteDialog(null);
    },
  });

  const reprocessTranslationMutation = useMutation({
    mutationFn: (translationId: number) => apiClient.reprocessDocumentTranslation(projectId, translationId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-translations", projectId] });
    },
  });

  const reprocessMutation = useMutation({
    mutationFn: (reportId: number) => apiClient.reprocessAnalysisReport(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["project-reports", projectId] });
    },
  });

  const askQuestionMutation = useMutation({
    mutationFn: ({ reportId, question }: { reportId: number; question: string }) => 
      apiClient.askReportQuestion(projectId, reportId, question),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["report-chat", selectedReport?.id] });
      setChatMessage("");
      setTimeout(() => {
        chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
      }, 100);
    },
  });

  const clearChatMutation = useMutation({
    mutationFn: (reportId: number) => apiClient.clearReportChat(projectId, reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["report-chat", selectedReport?.id] });
    },
  });

  // Drag and drop handlers
  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = Array.from(e.dataTransfer.files);
    if (activeTab === "files") {
      files.forEach((file) => {
        uploadFileMutation.mutate(file);
      });
    } else if (activeTab === "documents") {
      // For documents, add to selected files
      setSelectedFiles((prev) => [...prev, ...files]);
    } else {
      files.forEach((file) => {
        createTranslationMutation.mutate({ file });
      });
    }
  }, [activeTab, uploadFileMutation, createTranslationMutation]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>, type: "file" | "document" | "translation") => {
    const files = e.target.files;
    if (!files) return;
    
    if (type === "file") {
      Array.from(files).forEach((file) => {
        uploadFileMutation.mutate(file);
      });
    } else if (type === "document") {
      // For documents, add to selected files
      setSelectedFiles((prev) => [...prev, ...Array.from(files)]);
    } else {
      Array.from(files).forEach((file) => {
        createTranslationMutation.mutate({ file });
      });
    }
    
    // Reset input
    e.target.value = "";
  };

  const handleRemoveSelectedFile = (index: number) => {
    setSelectedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleStartAnalysis = () => {
    if (selectedFiles.length === 0) return;
    createReportMutation.mutate({ files: selectedFiles, prompt: customPrompt, depth: analysisDepth });
  };

  const handleAskQuestion = () => {
    if (!selectedReport || !chatMessage.trim()) return;
    askQuestionMutation.mutate({ reportId: selectedReport.id, question: chatMessage.trim() });
  };

  // Render rich text with markdown-like formatting
  const renderRichText = (text: string) => {
    if (!text) return null;
    
    // Simple markdown-like rendering
    const parts = text.split(/(\*\*[^*]+\*\*|\*[^*]+\*|•)/g);
    return parts.map((part, i) => {
      if (part.startsWith("**") && part.endsWith("**")) {
        return <strong key={i}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith("*") && part.endsWith("*")) {
        return <em key={i}>{part.slice(1, -1)}</em>;
      }
      if (part === "•") {
        return <span key={i}>•</span>;
      }
      return <span key={i}>{part}</span>;
    });
  };

  return (
    <Box>
      {/* Header */}
      <Paper
        sx={{
          p: 3,
          mb: 3,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.08)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)`,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }}
      >
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 2,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.2)} 0%, ${alpha(theme.palette.secondary.main, 0.2)} 100%)`,
              color: theme.palette.primary.main,
            }}
          >
            <FolderIcon sx={{ fontSize: 32 }} />
          </Box>
          <Box>
            <Typography variant="h5" fontWeight={700}>
              Project Files & Documents
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Store files and analyze documents with AI for {projectName}
            </Typography>
          </Box>
        </Stack>

        {/* Tabs */}
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          sx={{
            "& .MuiTabs-indicator": {
              height: 3,
              borderRadius: "3px 3px 0 0",
              background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
            },
          }}
        >
          <Tab
            value="files"
            icon={<InsertDriveFileIcon />}
            iconPosition="start"
            label={`Files (${filesQuery.data?.length || 0})`}
          />
          <Tab
            value="documents"
            icon={<AutoAwesomeIcon />}
            iconPosition="start"
            label={`AI Analysis (${reportsQuery.data?.length || 0})`}
          />
          <Tab
            value="translations"
            icon={<TranslateIcon />}
            iconPosition="start"
            label={`Document Translation (${translationsQuery.data?.length || 0})`}
          />
        </Tabs>
      </Paper>

      {/* File Storage Tab */}
      {activeTab === "files" && (
        <Box>
          {/* Upload Area */}
          {canEdit && (
            <Paper
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              sx={{
                p: 4,
                mb: 3,
                border: `2px dashed ${isDragging ? theme.palette.primary.main : alpha(theme.palette.divider, 0.3)}`,
                borderRadius: 2,
                textAlign: "center",
                cursor: "pointer",
                transition: "all 0.3s ease",
                bgcolor: isDragging ? alpha(theme.palette.primary.main, 0.05) : "transparent",
                "&:hover": {
                  borderColor: theme.palette.primary.main,
                  bgcolor: alpha(theme.palette.primary.main, 0.02),
                },
              }}
              onClick={() => fileInputRef.current?.click()}
            >
              <input
                ref={fileInputRef}
                type="file"
                multiple
                hidden
                onChange={(e) => handleFileSelect(e, "file")}
              />
              <CloudUploadIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
              <Typography variant="h6" gutterBottom>
                {isDragging ? "Drop files here" : "Drag & drop files here"}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                or click to browse • Max 500MB per file
              </Typography>
              {uploadProgress !== null && (
                <Box sx={{ mt: 2 }}>
                  <LinearProgress variant="determinate" value={uploadProgress} sx={{ borderRadius: 1 }} />
                  <Typography variant="caption" sx={{ mt: 0.5 }}>
                    Uploading... {uploadProgress}%
                  </Typography>
                </Box>
              )}
            </Paper>
          )}

          {/* File List */}
          {filesQuery.isLoading && (
            <Stack spacing={1}>
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} variant="rectangular" height={60} sx={{ borderRadius: 1 }} />
              ))}
            </Stack>
          )}

          {filesQuery.isError && (
            <Alert severity="error">Failed to load files</Alert>
          )}

          {filesQuery.data && filesQuery.data.length === 0 && (
            <Paper
              sx={{
                p: 6,
                textAlign: "center",
                border: `1px dashed ${alpha(theme.palette.divider, 0.3)}`,
              }}
            >
              <FolderIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                No files yet
              </Typography>
              <Typography variant="body2" color="text.disabled">
                Upload files to store them in this project
              </Typography>
            </Paper>
          )}

          {filesQuery.data && filesQuery.data.length > 0 && (
            <List sx={{ bgcolor: "background.paper", borderRadius: 2 }}>
              {filesQuery.data.map((file) => (
                <ListItem
                  key={file.id}
                  sx={{
                    borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                    "&:last-child": { borderBottom: "none" },
                    "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.03) },
                  }}
                >
                  <ListItemIcon
                    sx={{
                      color: theme.palette.primary.main,
                      minWidth: 48,
                    }}
                  >
                    {getFileIcon(file.mime_type, file.original_filename)}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Typography fontWeight={600}>
                        {file.original_filename}
                      </Typography>
                    }
                    secondary={
                      <Stack direction="row" spacing={1} alignItems="center">
                        <Typography variant="caption" color="text.secondary">
                          {formatFileSize(file.file_size)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">•</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(file.created_at).toLocaleDateString()}
                        </Typography>
                        {file.uploaded_by_username && (
                          <>
                            <Typography variant="caption" color="text.secondary">•</Typography>
                            <Typography variant="caption" color="text.secondary">
                              by {file.uploaded_by_username}
                            </Typography>
                          </>
                        )}
                      </Stack>
                    }
                  />
                  <ListItemSecondaryAction>
                    <Stack direction="row" spacing={1}>
                      <Tooltip title="Download">
                        <IconButton
                          size="small"
                          href={`/api${file.file_url}`}
                          download={file.original_filename}
                        >
                          <DownloadIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {canEdit && (
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            onClick={() => setDeleteDialog({ type: "file", id: file.id, name: file.original_filename })}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Stack>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          )}
        </Box>
      )}

      {/* AI Documents Tab */}
      {activeTab === "documents" && (
        <Box>
          {/* Upload Area for Multi-Document Analysis */}
          {canEdit && (
            <Paper
              sx={{
                p: 3,
                mb: 3,
                border: `2px dashed ${isDragging ? theme.palette.secondary.main : alpha(theme.palette.divider, 0.3)}`,
                borderRadius: 2,
                background: isDragging 
                  ? alpha(theme.palette.secondary.main, 0.05)
                  : `linear-gradient(135deg, ${alpha("#8b5cf6", 0.03)} 0%, ${alpha("#06b6d4", 0.03)} 100%)`,
              }}
            >
              <Box
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => documentInputRef.current?.click()}
                sx={{
                  textAlign: "center",
                  cursor: "pointer",
                  py: 2,
                }}
              >
                <input
                  ref={documentInputRef}
                  type="file"
                  multiple
                  hidden
                  accept=".pdf,.doc,.docx,.ppt,.pptx,.txt,.md,.csv,.json,.xml"
                  onChange={(e) => handleFileSelect(e, "document")}
                />
                <Stack direction="row" alignItems="center" justifyContent="center" spacing={1} sx={{ mb: 1 }}>
                  <AutoAwesomeIcon sx={{ color: "#8b5cf6" }} />
                  <Typography variant="h6" fontWeight={600}>
                    Upload Documents for AI Analysis
                  </Typography>
                </Stack>
                <Typography variant="body2" color="text.secondary">
                  PDF, Word, PowerPoint, Text • Select multiple files for combined analysis
                </Typography>
              </Box>

              {/* Selected Files Preview */}
              {selectedFiles.length > 0 && (
                <Box sx={{ mt: 3 }}>
                  <Divider sx={{ mb: 2 }} />
                  <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                    <AttachFileIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                    Selected Files ({selectedFiles.length})
                  </Typography>
                  <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 2 }}>
                    {selectedFiles.map((file, index) => (
                      <Chip
                        key={index}
                        label={file.name}
                        size="small"
                        onDelete={() => handleRemoveSelectedFile(index)}
                        icon={getFileIcon(file.type, file.name)}
                        sx={{ mb: 0.5 }}
                      />
                    ))}
                  </Stack>

                  {/* Custom Prompt Toggle */}
                  <Button
                    size="small"
                    startIcon={<TuneIcon />}
                    onClick={() => setShowPromptField(!showPromptField)}
                    sx={{ mb: 1 }}
                  >
                    {showPromptField ? "Hide" : "Add"} Custom Instructions
                  </Button>

                  <Collapse in={showPromptField}>
                    <TextField
                      fullWidth
                      multiline
                      rows={3}
                      placeholder="Add custom instructions for the AI analysis (e.g., 'Focus on financial data', 'Compare the contracts', 'Extract all dates and deadlines')"
                      value={customPrompt}
                      onChange={(e) => setCustomPrompt(e.target.value)}
                      sx={{ mb: 2 }}
                      InputProps={{
                        sx: { bgcolor: "background.paper" },
                      }}
                    />
                  </Collapse>

                  <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mb: 2 }}>
                    <TextField
                      select
                      label="Analysis Depth"
                      value={analysisDepth}
                      onChange={(e) => setAnalysisDepth(e.target.value as "standard" | "deep")}
                      size="small"
                      sx={{ minWidth: 220 }}
                      helperText={analysisDepth === "deep" ? "More detailed, slower" : "Faster, shorter"}
                    >
                      <MenuItem value="standard">Standard</MenuItem>
                      <MenuItem value="deep">Deep</MenuItem>
                    </TextField>
                  </Stack>

                  {/* Upload/Analyze Button */}
                  <Button
                    variant="contained"
                    size="large"
                    startIcon={createReportMutation.isPending ? <CircularProgress size={20} sx={{ color: "white" }} /> : <AutoAwesomeIcon />}
                    onClick={handleStartAnalysis}
                    disabled={createReportMutation.isPending}
                    sx={{
                      background: `linear-gradient(135deg, #8b5cf6 0%, #06b6d4 100%)`,
                      "&:hover": {
                        background: `linear-gradient(135deg, #7c3aed 0%, #0891b2 100%)`,
                      },
                    }}
                  >
                    {createReportMutation.isPending ? "Uploading..." : `Analyze ${selectedFiles.length} Document${selectedFiles.length > 1 ? "s" : ""}`}
                  </Button>

                  {uploadProgress !== null && (
                    <Box sx={{ mt: 2 }}>
                      <LinearProgress 
                        variant="determinate" 
                        value={uploadProgress} 
                        sx={{ 
                          borderRadius: 1,
                          bgcolor: alpha("#8b5cf6", 0.2),
                          "& .MuiLinearProgress-bar": {
                            background: `linear-gradient(90deg, #8b5cf6, #06b6d4)`,
                          },
                        }} 
                      />
                      <Typography variant="caption" sx={{ mt: 0.5 }}>
                        Uploading... {uploadProgress}%
                      </Typography>
                    </Box>
                  )}
                </Box>
              )}
            </Paper>
          )}

          {/* Analysis Reports List */}
          {reportsQuery.isLoading && (
            <Stack spacing={2}>
              {[1, 2].map((i) => (
                <Skeleton key={i} variant="rectangular" height={150} sx={{ borderRadius: 2 }} />
              ))}
            </Stack>
          )}

          {reportsQuery.data && reportsQuery.data.length === 0 && (
            <Paper
              sx={{
                p: 6,
                textAlign: "center",
                border: `1px dashed ${alpha(theme.palette.divider, 0.3)}`,
              }}
            >
              <AutoAwesomeIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                No analysis reports yet
              </Typography>
              <Typography variant="body2" color="text.disabled">
                Upload documents above to create an AI analysis report
              </Typography>
            </Paper>
          )}

          {reportsQuery.data && reportsQuery.data.length > 0 && (
            <Stack spacing={2}>
              {reportsQuery.data.map((report) => (
                <Accordion
                  key={report.id}
                  expanded={selectedReport?.id === report.id}
                  onChange={(_, expanded) => setSelectedReport(expanded ? report : null)}
                  sx={{
                    border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                    "&:before": { display: "none" },
                    borderRadius: "12px !important",
                    overflow: "hidden",
                  }}
                >
                  <AccordionSummary
                    expandIcon={<ExpandMoreIcon />}
                    sx={{
                      background: report.status === "completed"
                        ? `linear-gradient(135deg, ${alpha("#8b5cf6", 0.05)} 0%, ${alpha("#06b6d4", 0.03)} 100%)`
                        : undefined,
                    }}
                  >
                    <Stack direction="row" alignItems="center" spacing={2} sx={{ flex: 1, mr: 2 }}>
                      <Box
                        sx={{
                          width: 48,
                          height: 48,
                          borderRadius: 1.5,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          bgcolor: alpha(theme.palette.primary.main, 0.1),
                          color: theme.palette.primary.main,
                        }}
                      >
                        <FileCopyIcon />
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Typography fontWeight={600}>
                            Analysis Report
                          </Typography>
                          <Chip
                            size="small"
                            icon={getStatusIcon(report.status)}
                            label={report.status}
                            color={getStatusColor(report.status)}
                            variant="outlined"
                            sx={{ fontSize: "0.7rem" }}
                          />
                        </Stack>
                        <Typography variant="body2" color="text.secondary">
                          {report.documents.length} document{report.documents.length !== 1 ? "s" : ""} • 
                          {new Date(report.created_at).toLocaleDateString()} • 
                          {report.created_by_username}
                        </Typography>
                        {report.custom_prompt && (
                          <Typography variant="caption" color="text.secondary" sx={{ fontStyle: "italic" }}>
                            Prompt: {report.custom_prompt.substring(0, 50)}{report.custom_prompt.length > 50 ? "..." : ""}
                          </Typography>
                        )}
                      </Box>
                      <Stack direction="row" spacing={0.5}>
                        {report.status === "failed" && canEdit && (
                          <Tooltip title="Retry Analysis">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                reprocessMutation.mutate(report.id);
                              }}
                            >
                              <RefreshIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                        {canEdit && (
                          <Tooltip title="Delete Report">
                            <IconButton
                              size="small"
                              onClick={(e) => {
                                e.stopPropagation();
                                setDeleteDialog({ type: "report", id: report.id, name: "this analysis report" });
                              }}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </Stack>
                    </Stack>
                  </AccordionSummary>
                  <AccordionDetails sx={{ p: 0 }}>
                    {/* Documents in Report */}
                    <Box sx={{ p: 2, borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                      <Typography variant="subtitle2" fontWeight={600} sx={{ mb: 1 }}>
                        <AttachFileIcon sx={{ fontSize: 16, mr: 0.5, verticalAlign: "middle" }} />
                        Documents Analyzed
                      </Typography>
                      <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                        {report.documents.map((doc) => (
                          <Chip
                            key={doc.id}
                            label={doc.original_filename}
                            size="small"
                            icon={getFileIcon(doc.mime_type, doc.original_filename)}
                            component="a"
                            href={`/api${doc.file_url}`}
                            target="_blank"
                            clickable
                            sx={{ mb: 0.5 }}
                          />
                        ))}
                      </Stack>
                    </Box>

                    {/* Processing Status */}
                    {(report.status === "pending" || report.status === "processing") && (
                      <Box sx={{ p: 4, textAlign: "center" }}>
                        <CircularProgress sx={{ mb: 2 }} />
                        <Typography color="text.secondary">
                          AI is analyzing your documents...
                        </Typography>
                      </Box>
                    )}

                    {/* Error */}
                    {report.status === "failed" && (
                      <Box sx={{ p: 2 }}>
                        <Alert severity="error">
                          Analysis failed: {report.error_message}
                        </Alert>
                      </Box>
                    )}

                    {/* Analysis Results */}
                    {report.status === "completed" && report.combined_summary && (
                      <Box sx={{ p: 2 }}>
                        {/* Summary */}
                        <Box sx={{ mb: 3 }}>
                          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                            <ArticleIcon sx={{ color: "text.secondary", fontSize: 18 }} />
                            <Typography variant="subtitle2" fontWeight={600}>
                              Combined Analysis
                            </Typography>
                          </Stack>
                          <Typography 
                            variant="body2" 
                            color="text.secondary" 
                            sx={{ 
                              whiteSpace: "pre-wrap",
                              lineHeight: 1.7,
                            }}
                          >
                            {renderRichText(report.combined_summary)}
                          </Typography>
                        </Box>

                        {/* Key Points */}
                        {report.combined_key_points && report.combined_key_points.length > 0 && (
                          <Box sx={{ mb: 3 }}>
                            <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                              <LightbulbIcon sx={{ color: "#fbbf24", fontSize: 18 }} />
                              <Typography variant="subtitle2" fontWeight={600}>
                                Key Findings
                              </Typography>
                            </Stack>
                            <Stack spacing={0.5}>
                              {report.combined_key_points.map((point, idx) => (
                                <Typography 
                                  key={idx} 
                                  variant="body2" 
                                  color="text.secondary"
                                  sx={{ lineHeight: 1.6 }}
                                >
                                  {renderRichText(point)}
                                </Typography>
                              ))}
                            </Stack>
                          </Box>
                        )}

                        <Divider sx={{ my: 2 }} />

                        {/* Chat Section */}
                        <Box>
                          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
                            <Stack direction="row" alignItems="center" spacing={1}>
                              <ChatIcon sx={{ color: "text.secondary", fontSize: 18 }} />
                              <Typography variant="subtitle2" fontWeight={600}>
                                Ask Questions
                              </Typography>
                            </Stack>
                            {chatQuery.data && chatQuery.data.length > 0 && (
                              <Tooltip title="Clear chat history">
                                <IconButton
                                  size="small"
                                  onClick={() => clearChatMutation.mutate(report.id)}
                                >
                                  <DeleteSweepIcon fontSize="small" />
                                </IconButton>
                              </Tooltip>
                            )}
                          </Stack>

                          {chatQuery.isLoading && (
                            <Stack spacing={1}>
                              <Skeleton variant="rectangular" height={60} sx={{ borderRadius: 2 }} />
                              <Skeleton variant="rectangular" height={80} sx={{ borderRadius: 2, ml: 4 }} />
                            </Stack>
                          )}

                          {chatQuery.data && chatQuery.data.length === 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                textAlign: "center",
                                bgcolor: alpha(theme.palette.info.main, 0.05),
                                border: `1px dashed ${alpha(theme.palette.info.main, 0.2)}`,
                                mb: 2,
                              }}
                            >
                              <SmartToyIcon sx={{ fontSize: 40, color: "text.disabled", mb: 1 }} />
                              <Typography variant="body2" color="text.secondary">
                                Ask me anything about these documents!
                              </Typography>
                              <Typography variant="caption" color="text.disabled">
                                Example: "Compare the key findings" or "What dates are mentioned?"
                              </Typography>
                            </Paper>
                          )}

                          {/* Chat Messages */}
                          {chatQuery.data && chatQuery.data.length > 0 && (
                            <Box 
                              sx={{ 
                                maxHeight: 400, 
                                overflowY: "auto", 
                                mb: 2,
                                p: 1,
                                bgcolor: alpha(theme.palette.background.default, 0.5),
                                borderRadius: 2,
                              }}
                            >
                              <Stack spacing={2}>
                                {chatQuery.data.map((msg) => (
                                  <Box
                                    key={msg.id}
                                    sx={{
                                      display: "flex",
                                      justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                                    }}
                                  >
                                    <Box
                                      sx={{
                                        maxWidth: "85%",
                                        p: 2,
                                        borderRadius: 2,
                                        bgcolor: msg.role === "user"
                                          ? alpha(theme.palette.primary.main, 0.1)
                                          : alpha("#8b5cf6", 0.08),
                                        border: `1px solid ${msg.role === "user" 
                                          ? alpha(theme.palette.primary.main, 0.2)
                                          : alpha("#8b5cf6", 0.15)}`,
                                      }}
                                    >
                                      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
                                        {msg.role === "assistant" ? (
                                          <SmartToyIcon sx={{ fontSize: 16, color: "#8b5cf6" }} />
                                        ) : (
                                          <Avatar sx={{ width: 20, height: 20, fontSize: 10 }}>
                                            {msg.username?.[0]?.toUpperCase() || "U"}
                                          </Avatar>
                                        )}
                                        <Typography variant="caption" fontWeight={600}>
                                          {msg.role === "assistant" ? "AI Assistant" : msg.username || "You"}
                                        </Typography>
                                      </Stack>
                                      <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                                        {renderRichText(msg.content)}
                                      </Typography>
                                    </Box>
                                  </Box>
                                ))}
                                <div ref={chatEndRef} />
                              </Stack>
                            </Box>
                          )}

                          {/* Chat Input */}
                          <Stack direction="row" spacing={1}>
                            <TextField
                              fullWidth
                              size="small"
                              placeholder="Ask a question about these documents..."
                              value={chatMessage}
                              onChange={(e) => setChatMessage(e.target.value)}
                              onKeyPress={(e) => {
                                if (e.key === "Enter" && !e.shiftKey) {
                                  e.preventDefault();
                                  handleAskQuestion();
                                }
                              }}
                              disabled={askQuestionMutation.isPending}
                            />
                            <Button
                              variant="contained"
                              onClick={handleAskQuestion}
                              disabled={!chatMessage.trim() || askQuestionMutation.isPending}
                              sx={{
                                minWidth: 48,
                                background: `linear-gradient(135deg, #8b5cf6 0%, #06b6d4 100%)`,
                              }}
                            >
                              {askQuestionMutation.isPending ? (
                                <CircularProgress size={20} sx={{ color: "white" }} />
                              ) : (
                                <SendIcon />
                              )}
                            </Button>
                          </Stack>
                        </Box>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </Stack>
          )}
        </Box>
      )}

      {/* Document Translation Tab */}
      {activeTab === "translations" && (
        <Box>
          {canEdit && (
            <Paper
              sx={{
                p: 3,
                mb: 3,
                border: `2px dashed ${isDragging ? theme.palette.info.main : alpha(theme.palette.divider, 0.3)}`,
                borderRadius: 2,
                background: isDragging
                  ? alpha(theme.palette.info.main, 0.05)
                  : `linear-gradient(135deg, ${alpha("#0ea5e9", 0.04)} 0%, ${alpha("#22c55e", 0.03)} 100%)`,
              }}
            >
              <Stack spacing={2}>
                <Stack direction={{ xs: "column", md: "row" }} spacing={2}>
                  <TextField
                    label="Target Language"
                    size="small"
                    value={translationTargetLanguage}
                    onChange={(e) => setTranslationTargetLanguage(e.target.value)}
                    placeholder="English"
                    sx={{ flex: 1 }}
                  />
                  <TextField
                    label="Source Language (optional)"
                    size="small"
                    value={translationSourceLanguage}
                    onChange={(e) => setTranslationSourceLanguage(e.target.value)}
                    placeholder="Auto-detect"
                    sx={{ flex: 1 }}
                  />
                  <TextField
                    label="OCR Languages (tesseract)"
                    size="small"
                    value={translationOcrLanguages}
                    onChange={(e) => setTranslationOcrLanguages(e.target.value)}
                    placeholder="rus+eng"
                    helperText="Use tesseract codes for OCR"
                    sx={{ flex: 1 }}
                  />
                </Stack>

                <Box
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => translationInputRef.current?.click()}
                  sx={{
                    textAlign: "center",
                    cursor: "pointer",
                    py: 2,
                  }}
                >
                  <input
                    ref={translationInputRef}
                    type="file"
                    multiple
                    hidden
                    accept=".pdf,.doc,.docx,.ppt,.pptx,.txt,.md,.csv,.json,.xml,.png,.jpg,.jpeg,.tiff,.bmp"
                    onChange={(e) => handleFileSelect(e, "translation")}
                  />
                  <Stack direction="row" alignItems="center" justifyContent="center" spacing={1} sx={{ mb: 1 }}>
                    <TranslateIcon sx={{ color: "#0ea5e9" }} />
                    <Typography variant="h6" fontWeight={600}>
                      Upload Documents for Translation
                    </Typography>
                  </Stack>
                  <Typography variant="body2" color="text.secondary">
                    PDF, Word, images • OCR supported with tesseract
                  </Typography>
                </Box>

                {translationProgress !== null && (
                  <Box sx={{ mt: 1 }}>
                    <LinearProgress
                      variant="determinate"
                      value={translationProgress}
                      sx={{
                        borderRadius: 1,
                        bgcolor: alpha("#0ea5e9", 0.2),
                        "& .MuiLinearProgress-bar": {
                          background: `linear-gradient(90deg, #0ea5e9, #22c55e)`,
                        },
                      }}
                    />
                    <Typography variant="caption" sx={{ mt: 0.5 }}>
                      Uploading... {translationProgress}%
                    </Typography>
                  </Box>
                )}
              </Stack>
            </Paper>
          )}

          {translationsQuery.isLoading && (
            <Stack spacing={2}>
              {[1, 2].map((i) => (
                <Skeleton key={i} variant="rectangular" height={120} sx={{ borderRadius: 2 }} />
              ))}
            </Stack>
          )}

          {translationsQuery.data && translationsQuery.data.length === 0 && (
            <Paper
              sx={{
                p: 6,
                textAlign: "center",
                border: `1px dashed ${alpha(theme.palette.divider, 0.3)}`,
              }}
            >
              <TranslateIcon sx={{ fontSize: 64, color: "text.disabled", mb: 2 }} />
              <Typography variant="h6" color="text.secondary">
                No translations yet
              </Typography>
              <Typography variant="body2" color="text.disabled">
                Upload a document to generate a translation
              </Typography>
            </Paper>
          )}

          {translationsQuery.data && translationsQuery.data.length > 0 && (
            <Stack spacing={2}>
              {translationsQuery.data.map((tr) => (
                <Paper
                  key={tr.id}
                  sx={{
                    p: 2,
                    border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  }}
                >
                  <Stack direction="row" spacing={2} alignItems="center" justifyContent="space-between">
                    <Stack direction="row" spacing={2} alignItems="center">
                      <Box
                        sx={{
                          width: 44,
                          height: 44,
                          borderRadius: 1.5,
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          bgcolor: alpha(theme.palette.info.main, 0.1),
                          color: theme.palette.info.main,
                        }}
                      >
                        <TranslateIcon />
                      </Box>
                      <Box>
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Typography fontWeight={600}>
                            {tr.original_filename}
                          </Typography>
                          <Chip
                            size="small"
                            icon={getStatusIcon(tr.status)}
                            label={tr.status}
                            color={getStatusColor(tr.status)}
                            variant="outlined"
                            sx={{ fontSize: "0.7rem" }}
                          />
                        </Stack>
                        <Typography variant="body2" color="text.secondary">
                          Target: {tr.target_language}
                          {tr.ocr_used ? " • OCR used" : ""}
                          {tr.page_count ? ` • ${tr.page_count} pages` : ""}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {formatFileSize(tr.file_size)} • {new Date(tr.created_at).toLocaleDateString()}
                        </Typography>
                      </Box>
                    </Stack>
                    <Stack direction="row" spacing={0.5}>
                      {tr.status === "failed" && canEdit && (
                        <Tooltip title="Retry Translation">
                          <IconButton
                            size="small"
                            onClick={() => reprocessTranslationMutation.mutate(tr.id)}
                          >
                            <RefreshIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {tr.output_url && (
                        <Tooltip title="Download Translation">
                          <IconButton
                            size="small"
                            href={tr.output_url}
                            download={tr.output_filename || undefined}
                          >
                            <DownloadIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {canEdit && (
                        <Tooltip title="Delete Translation">
                          <IconButton
                            size="small"
                            onClick={() =>
                              setDeleteDialog({ type: "translation", id: tr.id, name: "this translation" })
                            }
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Stack>
                  </Stack>
                  {tr.status === "failed" && tr.error_message && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      Translation failed: {tr.error_message}
                    </Alert>
                  )}
                </Paper>
              ))}
            </Stack>
          )}
        </Box>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={!!deleteDialog} onClose={() => setDeleteDialog(null)}>
        <DialogTitle>
          Delete {deleteDialog?.type === "file" ? "File" : deleteDialog?.type === "translation" ? "Translation" : "Analysis Report"}?
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete <strong>{deleteDialog?.name}</strong>?
            {deleteDialog?.type === "report" && " This will also delete all documents and chat history in this report."}
            This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialog(null)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => {
              if (deleteDialog?.type === "file") {
                deleteFileMutation.mutate(deleteDialog.id);
              } else if (deleteDialog?.type === "report") {
                deleteReportMutation.mutate(deleteDialog.id);
              } else if (deleteDialog?.type === "translation") {
                deleteTranslationMutation.mutate(deleteDialog.id);
              }
            }}
            disabled={
              deleteFileMutation.isPending
              || deleteReportMutation.isPending
              || deleteTranslationMutation.isPending
            }
          >
            {deleteFileMutation.isPending || deleteReportMutation.isPending || deleteTranslationMutation.isPending
              ? "Deleting..."
              : "Delete"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
