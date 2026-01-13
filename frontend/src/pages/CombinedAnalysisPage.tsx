import { useState, useRef } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  AlertTitle,
  Box,
  Button,
  Card,
  CardContent,
  Checkbox,
  Chip,
  CircularProgress,
  Collapse,
  Divider,
  FormControlLabel,
  Grid,
  IconButton,
  LinearProgress,
  Paper,
  Skeleton,
  Stack,
  Tab,
  Tabs,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  keyframes,
  Switch,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import CodeIcon from "@mui/icons-material/Code";
import DownloadIcon from "@mui/icons-material/Download";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import DescriptionIcon from "@mui/icons-material/Description";
import ArticleIcon from "@mui/icons-material/Article";
import SendIcon from "@mui/icons-material/Send";
import ChatIcon from "@mui/icons-material/Chat";
import ReactMarkdown from "react-markdown";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { vscDarkPlus } from "react-syntax-highlighter/dist/esm/styles/prism";
import {
  combinedAnalysisApi,
  AvailableScanItem,
  SelectedScan,
  CombinedAnalysisReport,
  CombinedAnalysisRequest,
  SupportingDocument,
} from "../api/client";
import { MermaidDiagram } from "../components/MermaidDiagram";

// Custom code block renderer for ReactMarkdown with syntax highlighting
const CodeBlock = ({ node, inline, className, children, ...props }: any) => {
  const match = /language-(\w+)/.exec(className || "");
  const language = match ? match[1] : "";
  const codeContent = String(children).replace(/\n$/, "");
  
  if (!inline && (language || codeContent.includes("\n") || codeContent.length > 80)) {
    return (
      <SyntaxHighlighter
        style={vscDarkPlus}
        language={language || "text"}
        PreTag="div"
        customStyle={{
          margin: "1rem 0",
          borderRadius: "8px",
          fontSize: "0.85rem",
          maxHeight: "500px",
          overflow: "auto",
        }}
        {...props}
      >
        {codeContent}
      </SyntaxHighlighter>
    );
  }
  
  // Inline code
  return (
    <code
      style={{
        backgroundColor: "rgba(0, 0, 0, 0.3)",
        color: "#fbbf24",
        padding: "2px 6px",
        borderRadius: "4px",
        fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
        fontSize: "0.85rem",
      }}
      {...props}
    >
      {children}
    </code>
  );
};

// Custom ReactMarkdown components for better rendering
const markdownComponents = {
  code: CodeBlock,
  h1: ({ children }: any) => (
    <Typography variant="h4" fontWeight={700} sx={{ mt: 3, mb: 2, color: "primary.main" }}>
      {children}
    </Typography>
  ),
  h2: ({ children }: any) => (
    <Typography variant="h5" fontWeight={600} sx={{ mt: 2.5, mb: 1.5, color: "text.primary" }}>
      {children}
    </Typography>
  ),
  h3: ({ children }: any) => (
    <Typography variant="h6" fontWeight={600} sx={{ mt: 2, mb: 1 }}>
      {children}
    </Typography>
  ),
  p: ({ children }: any) => (
    <Typography sx={{ mb: 1.5, lineHeight: 1.7 }}>{children}</Typography>
  ),
  ul: ({ children }: any) => (
    <Box component="ul" sx={{ pl: 3, mb: 2 }}>{children}</Box>
  ),
  ol: ({ children }: any) => (
    <Box component="ol" sx={{ pl: 3, mb: 2 }}>{children}</Box>
  ),
  li: ({ children }: any) => (
    <Typography component="li" sx={{ mb: 0.5, lineHeight: 1.6 }}>{children}</Typography>
  ),
  strong: ({ children }: any) => (
    <Box component="strong" sx={{ fontWeight: 700, color: "warning.light" }}>{children}</Box>
  ),
  blockquote: ({ children }: any) => (
    <Box
      component="blockquote"
      sx={{
        borderLeft: "4px solid",
        borderColor: "primary.main",
        pl: 2,
        py: 1,
        my: 2,
        bgcolor: "rgba(0, 0, 0, 0.1)",
        borderRadius: "0 8px 8px 0",
      }}
    >
      {children}
    </Box>
  ),
  a: ({ href, children }: any) => (
    <Box
      component="a"
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      sx={{
        color: "info.light",
        textDecoration: "underline",
        "&:hover": { color: "info.main" },
      }}
    >
      {children}
    </Box>
  ),
};

// Animations
const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
`;

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.5; }
`;

const shimmer = keyframes`
  0% { background-position: -200% center; }
  100% { background-position: 200% center; }
`;

// Icons
const BackIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z" />
  </svg>
);

const ExpandIcon = ({ expanded }: { expanded: boolean }) => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="currentColor"
    style={{
      transform: expanded ? "rotate(180deg)" : "rotate(0deg)",
      transition: "transform 0.3s ease",
    }}
  >
    <path d="M16.59 8.59L12 13.17 7.41 8.59 6 10l6 6 6-6z" />
  </svg>
);

const SecurityIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
  </svg>
);

const NetworkIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M17 16l-4-4V8.82C14.16 8.4 15 7.3 15 6c0-1.66-1.34-3-3-3S9 4.34 9 6c0 1.3.84 2.4 2 2.82V12l-4 4H3v5h5v-3.05l4-4.2 4 4.2V21h5v-5h-4z" />
  </svg>
);

const REIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z" />
  </svg>
);

const FuzzIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 8h-2.81c-.45-.78-1.07-1.45-1.82-1.96L17 4.41 15.59 3l-2.17 2.17C12.96 5.06 12.49 5 12 5c-.49 0-.96.06-1.41.17L8.41 3 7 4.41l1.62 1.63C7.88 6.55 7.26 7.22 6.81 8H4v2h2.09c-.05.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81c1.04 1.79 2.97 3 5.19 3s4.15-1.21 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20V8zm-6 8h-4v-2h4v2zm0-4h-4v-2h4v2z" />
  </svg>
);

const SSLIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 1.39-3.1 3.1-3.1 1.71 0 3.1 1.39 3.1 3.1v2z" />
  </svg>
);

const DnsIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
  </svg>
);

const TracerouteIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M17 16l-4-4V8.82C14.16 8.4 15 7.3 15 6c0-1.66-1.34-3-3-3S9 4.34 9 6c0 1.3.84 2.4 2 2.82V12l-4 4H3v5h5v-3.05l4-4.2 4 4.2V21h5v-5h-4z" />
  </svg>
);

const UploadIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z" />
  </svg>
);

const ReportIcon = () => (
  <svg width="32" height="32" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm-5 14H7v-2h7v2zm3-4H7v-2h10v2zm0-4H7V7h10v2z" />
  </svg>
);

const ExploitIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-2 15l-5-5 1.41-1.41L10 14.17l7.59-7.59L19 8l-9 9z" />
  </svg>
);

const DeleteIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z" />
  </svg>
);

// Risk level color helper
const getRiskColor = (level: string, theme: any) => {
  const lowerLevel = level.toLowerCase();
  if (lowerLevel === "critical") return theme.palette.error.main;
  if (lowerLevel === "high") return "#f97316";
  if (lowerLevel === "medium") return theme.palette.warning.main;
  if (lowerLevel === "low") return theme.palette.info.main;
  if (lowerLevel === "clean") return theme.palette.success.main;
  return theme.palette.grey[500];
};

// Tab panel helper
function TabPanel(props: { children?: React.ReactNode; index: number; value: number }) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ py: 2 }}>{children}</Box>}
    </div>
  );
}

export default function CombinedAnalysisPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const theme = useTheme();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // State
  const [selectedScans, setSelectedScans] = useState<SelectedScan[]>([]);
  const [reportTitle, setReportTitle] = useState("");
  const [projectInfo, setProjectInfo] = useState("");
  const [userRequirements, setUserRequirements] = useState("");
  const [supportingDocs, setSupportingDocs] = useState<SupportingDocument[]>([]);
  const [includeExploits, setIncludeExploits] = useState(true);
  const [includeAttackSurface, setIncludeAttackSurface] = useState(true);
  const [includeRiskPriority, setIncludeRiskPriority] = useState(true);
  const [activeTab, setActiveTab] = useState(0);
  const [selectedReport, setSelectedReport] = useState<CombinedAnalysisReport | null>(null);
  const [expandedSections, setExpandedSections] = useState<string[]>([]);
  const [exportLoading, setExportLoading] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: "success" | "error" }>({
    open: false,
    message: "",
    severity: "success",
  });

  // Fetch available scans
  const availableScansQuery = useQuery({
    queryKey: ["combined-analysis-scans", projectId],
    queryFn: () => combinedAnalysisApi.getAvailableScans(Number(projectId)),
    enabled: !!projectId,
  });

  // Fetch existing reports
  const existingReportsQuery = useQuery({
    queryKey: ["combined-analysis-reports", projectId],
    queryFn: () => combinedAnalysisApi.listReports(Number(projectId)),
    enabled: !!projectId,
  });

  // Generate report mutation
  const generateMutation = useMutation({
    mutationFn: (request: CombinedAnalysisRequest) =>
      combinedAnalysisApi.generateReport(Number(projectId), request),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["combined-analysis-reports", projectId] });
      setSelectedReport(data);
      setActiveTab(2); // Switch to report view
    },
  });

  // Delete report mutation
  const deleteMutation = useMutation({
    mutationFn: (reportId: number) => combinedAnalysisApi.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["combined-analysis-reports", projectId] });
      setSelectedReport(null);
    },
  });

  // Export handlers
  const handleExportMarkdown = async () => {
    if (!selectedReport) return;
    setExportLoading("markdown");
    try {
      const blob = await combinedAnalysisApi.exportMarkdown(selectedReport.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${selectedReport.title.replace(/[^a-zA-Z0-9 -_]/g, "_")}_report.md`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSnackbar({ open: true, message: "Markdown export downloaded successfully!", severity: "success" });
    } catch (error) {
      setSnackbar({ open: true, message: `Export failed: ${error}`, severity: "error" });
    } finally {
      setExportLoading(null);
    }
  };

  const handleExportWord = async () => {
    if (!selectedReport) return;
    setExportLoading("word");
    try {
      const blob = await combinedAnalysisApi.exportWord(selectedReport.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${selectedReport.title.replace(/[^a-zA-Z0-9 -_]/g, "_")}_report.docx`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSnackbar({ open: true, message: "Word document downloaded successfully!", severity: "success" });
    } catch (error) {
      setSnackbar({ open: true, message: `Export failed: ${error}`, severity: "error" });
    } finally {
      setExportLoading(null);
    }
  };

  const handleExportPdf = async () => {
    if (!selectedReport) return;
    setExportLoading("pdf");
    try {
      const blob = await combinedAnalysisApi.exportPdf(selectedReport.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${selectedReport.title.replace(/[^a-zA-Z0-9 -_]/g, "_")}_report.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSnackbar({ open: true, message: "PDF downloaded successfully!", severity: "success" });
    } catch (error) {
      setSnackbar({ open: true, message: `Export failed: ${error}`, severity: "error" });
    } finally {
      setExportLoading(null);
    }
  };

  const handleSendToTeamChat = async () => {
    if (!selectedReport) return;
    setExportLoading("chat");
    try {
      await combinedAnalysisApi.sendToTeamChat(selectedReport.id);
      setSnackbar({ open: true, message: "Report summary sent to team chat!", severity: "success" });
    } catch (error) {
      setSnackbar({ open: true, message: `Failed to send to team chat: ${error}`, severity: "error" });
    } finally {
      setExportLoading(null);
    }
  };

  // Handle scan selection
  const handleToggleScan = (scan: AvailableScanItem, scanType: string) => {
    const existing = selectedScans.find(
      (s) => s.scan_type === scanType && s.scan_id === scan.scan_id
    );
    if (existing) {
      setSelectedScans(selectedScans.filter((s) => s !== existing));
    } else {
      setSelectedScans([
        ...selectedScans,
        {
          scan_type: scanType as SelectedScan["scan_type"],
          scan_id: scan.scan_id,
          title: scan.title,
        },
      ]);
    }
  };

  // Handle select all for a category
  const handleSelectAll = (scans: AvailableScanItem[], scanType: string) => {
    const allSelected = scans.every((scan) =>
      selectedScans.some((s) => s.scan_type === scanType && s.scan_id === scan.scan_id)
    );

    if (allSelected) {
      // Deselect all
      setSelectedScans(selectedScans.filter((s) => s.scan_type !== scanType));
    } else {
      // Select all
      const newScans = scans
        .filter(
          (scan) =>
            !selectedScans.some((s) => s.scan_type === scanType && s.scan_id === scan.scan_id)
        )
        .map((scan) => ({
          scan_type: scanType as SelectedScan["scan_type"],
          scan_id: scan.scan_id,
          title: scan.title,
        }));
      setSelectedScans([...selectedScans, ...newScans]);
    }
  };

  // Handle file upload
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    for (const file of Array.from(files)) {
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = (reader.result as string).split(",")[1];
        setSupportingDocs((prev) => [
          ...prev,
          {
            filename: file.name,
            content_type: file.type || "application/octet-stream",
            content_base64: base64,
          },
        ]);
      };
      reader.readAsDataURL(file);
    }

    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  // Handle generate report
  const handleGenerate = () => {
    if (!reportTitle.trim()) {
      alert("Please enter a report title");
      return;
    }
    if (selectedScans.length === 0) {
      alert("Please select at least one scan");
      return;
    }

    const request: CombinedAnalysisRequest = {
      project_id: Number(projectId),
      title: reportTitle,
      selected_scans: selectedScans,
      supporting_documents: supportingDocs.length > 0 ? supportingDocs : undefined,
      project_info: projectInfo || undefined,
      user_requirements: userRequirements || undefined,
      include_exploit_recommendations: includeExploits,
      include_attack_surface_map: includeAttackSurface,
      include_risk_prioritization: includeRiskPriority,
    };

    generateMutation.mutate(request);
  };

  // View an existing report
  const handleViewReport = async (reportId: number) => {
    const report = await combinedAnalysisApi.getReport(reportId);
    setSelectedReport(report);
    setActiveTab(2);
  };

  // Render scan category
  const renderScanCategory = (
    title: string,
    icon: React.ReactNode,
    scans: AvailableScanItem[],
    scanType: string,
    color: string
  ) => {
    if (scans.length === 0) return null;

    const allSelected = scans.every((scan) =>
      selectedScans.some((s) => s.scan_type === scanType && s.scan_id === scan.scan_id)
    );

    return (
      <Card
        sx={{
          mb: 2,
          background: `linear-gradient(135deg, ${alpha(color, 0.05)} 0%, ${alpha(color, 0.02)} 100%)`,
          border: `1px solid ${alpha(color, 0.2)}`,
          borderRadius: 2,
        }}
      >
        <CardContent>
          <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
            <Stack direction="row" alignItems="center" spacing={1.5}>
              <Box sx={{ color }}>{icon}</Box>
              <Typography variant="h6" fontWeight={600}>
                {title}
              </Typography>
              <Chip label={scans.length} size="small" sx={{ bgcolor: alpha(color, 0.1), color }} />
            </Stack>
            <FormControlLabel
              control={
                <Checkbox
                  checked={allSelected}
                  onChange={() => handleSelectAll(scans, scanType)}
                  sx={{ color, "&.Mui-checked": { color } }}
                />
              }
              label="Select All"
            />
          </Stack>

          <Grid container spacing={1.5}>
            {scans.map((scan) => {
              const isSelected = selectedScans.some(
                (s) => s.scan_type === scanType && s.scan_id === scan.scan_id
              );

              return (
                <Grid item xs={12} sm={6} md={4} key={`${scanType}-${scan.scan_id}`}>
                  <Paper
                    onClick={() => handleToggleScan(scan, scanType)}
                    sx={{
                      p: 1.5,
                      cursor: "pointer",
                      transition: "all 0.2s ease",
                      border: `2px solid ${isSelected ? color : "transparent"}`,
                      bgcolor: isSelected ? alpha(color, 0.08) : alpha(theme.palette.background.paper, 0.5),
                      "&:hover": {
                        bgcolor: alpha(color, 0.1),
                        transform: "translateY(-2px)",
                      },
                    }}
                  >
                    <Stack direction="row" alignItems="flex-start" spacing={1}>
                      <Checkbox
                        checked={isSelected}
                        size="small"
                        sx={{ p: 0, color, "&.Mui-checked": { color } }}
                      />
                      <Box sx={{ flex: 1, minWidth: 0 }}>
                        <Typography
                          variant="body2"
                          fontWeight={600}
                          sx={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {scan.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(scan.created_at).toLocaleDateString()}
                        </Typography>
                        {scan.risk_level && (
                          <Chip
                            label={scan.risk_level}
                            size="small"
                            sx={{
                              ml: 1,
                              height: 18,
                              fontSize: "0.65rem",
                              bgcolor: alpha(getRiskColor(scan.risk_level, theme), 0.15),
                              color: getRiskColor(scan.risk_level, theme),
                            }}
                          />
                        )}
                        {scan.findings_count != null && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 0.5 }}>
                            {scan.findings_count} findings
                          </Typography>
                        )}
                      </Box>
                    </Stack>
                  </Paper>
                </Grid>
              );
            })}
          </Grid>
        </CardContent>
      </Card>
    );
  };

  // Render generated report
  const renderReport = () => {
    if (!selectedReport) return null;

    return (
      <Box sx={{ animation: `${fadeIn} 0.4s ease` }}>
        {/* Header */}
        <Paper
          sx={{
            p: 3,
            mb: 3,
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.05)} 100%)`,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            borderRadius: 3,
          }}
        >
          {/* Title and Info */}
          <Box sx={{ mb: 2 }}>
            <Typography variant="h4" fontWeight={700} gutterBottom>
              {selectedReport.title}
            </Typography>
            <Typography color="text.secondary">
              Generated: {new Date(selectedReport.created_at).toLocaleString()}
            </Typography>
            <Stack direction="row" spacing={2} sx={{ mt: 2 }} flexWrap="wrap">
              <Chip
                label={`Risk: ${selectedReport.overall_risk_level}`}
                sx={{
                  bgcolor: alpha(getRiskColor(selectedReport.overall_risk_level, theme), 0.15),
                  color: getRiskColor(selectedReport.overall_risk_level, theme),
                  fontWeight: 600,
                }}
              />
              <Chip
                label={`Score: ${selectedReport.overall_risk_score}/100`}
                variant="outlined"
              />
              <Chip
                label={`${selectedReport.total_findings_analyzed} Findings Analyzed`}
                variant="outlined"
              />
              <Chip
                label={`${selectedReport.scans_included} Scans Included`}
                variant="outlined"
              />
            </Stack>
          </Box>
          
          {/* Action Buttons - Full Width Row */}
          <Divider sx={{ my: 2 }} />
          <Box sx={{ 
            p: 2, 
            bgcolor: alpha(theme.palette.info.main, 0.08), 
            borderRadius: 2,
            border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`
          }}>
            <Typography variant="subtitle2" sx={{ mb: 1.5, fontWeight: 600 }}>
              📤 Export & Share
            </Typography>
            <Stack direction="row" spacing={2} justifyContent="space-between" alignItems="center" flexWrap="wrap">
              {/* Export Buttons */}
              <Stack direction="row" spacing={1} flexWrap="wrap">
                <Tooltip title="Export as Markdown">
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={exportLoading === "markdown" ? <CircularProgress size={16} /> : <ArticleIcon />}
                  onClick={handleExportMarkdown}
                  disabled={!!exportLoading}
                >
                  Markdown
                </Button>
              </Tooltip>
              <Tooltip title="Export as Word Document">
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={exportLoading === "word" ? <CircularProgress size={16} /> : <DescriptionIcon />}
                  onClick={handleExportWord}
                  disabled={!!exportLoading}
                >
                  Word
                </Button>
              </Tooltip>
              <Tooltip title="Export as PDF">
                <Button
                  size="small"
                  variant="outlined"
                  startIcon={exportLoading === "pdf" ? <CircularProgress size={16} /> : <PictureAsPdfIcon />}
                  onClick={handleExportPdf}
                  disabled={!!exportLoading}
                >
                  PDF
                </Button>
              </Tooltip>
            </Stack>
            {/* Team Chat & Delete */}
            <Stack direction="row" spacing={1}>
              <Tooltip title="Send report summary to project team chat">
                <Button
                  size="small"
                  variant="contained"
                  color="primary"
                  startIcon={exportLoading === "chat" ? <CircularProgress size={16} color="inherit" /> : <ChatIcon />}
                  onClick={handleSendToTeamChat}
                  disabled={!!exportLoading}
                >
                  Send to Team
                </Button>
              </Tooltip>
              <Tooltip title="Delete Report">
                <IconButton
                  onClick={() => deleteMutation.mutate(selectedReport.id)}
                  disabled={deleteMutation.isPending}
                  sx={{ color: theme.palette.error.main }}
                >
                  <DeleteIcon />
                </IconButton>
              </Tooltip>
            </Stack>
          </Stack>
          </Box>
        </Paper>

        {/* Executive Summary */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="h5" fontWeight={600} gutterBottom>
              📋 Executive Summary
            </Typography>
            <Divider sx={{ my: 2 }} />
            <Box
              sx={{
                "& pre": {
                  bgcolor: "rgba(0, 0, 0, 0.4) !important",
                  borderRadius: 2,
                  p: 2,
                  overflow: "auto",
                  "& code": {
                    color: "success.light",
                    fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
                    fontSize: "0.85rem",
                  },
                },
              }}
            >
              <ReactMarkdown components={markdownComponents}>{selectedReport.executive_summary}</ReactMarkdown>
            </Box>
          </CardContent>
        </Card>

        {/* Risk Justification */}
        {selectedReport.risk_justification && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom>
                ⚠️ Risk Assessment Justification
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Typography>{selectedReport.risk_justification}</Typography>
            </CardContent>
          </Card>
        )}

        {/* Report Sections */}
        {selectedReport.sections && selectedReport.sections.length > 0 && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom>
                📑 Detailed Analysis
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.sections.map((section, idx) => (
                <Accordion
                  key={idx}
                  expanded={expandedSections.includes(`section-${idx}`)}
                  onChange={() => {
                    setExpandedSections((prev) =>
                      prev.includes(`section-${idx}`)
                        ? prev.filter((s) => s !== `section-${idx}`)
                        : [...prev, `section-${idx}`]
                    );
                  }}
                  sx={{
                    mb: 1,
                    "&:before": { display: "none" },
                    boxShadow: "none",
                    border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  }}
                >
                  <AccordionSummary expandIcon={<ExpandIcon expanded={expandedSections.includes(`section-${idx}`)} />}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <Typography fontWeight={600}>{section.title}</Typography>
                      {section.severity && (
                        <Chip
                          label={section.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getRiskColor(section.severity, theme), 0.15),
                            color: getRiskColor(section.severity, theme),
                            height: 20,
                            fontSize: "0.7rem",
                          }}
                        />
                      )}
                    </Stack>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box
                      sx={{
                        "& pre": {
                          bgcolor: "rgba(0, 0, 0, 0.4) !important",
                          borderRadius: 2,
                          p: 2,
                          overflow: "auto",
                          "& code": {
                            color: "success.light",
                            fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
                            fontSize: "0.85rem",
                          },
                        },
                      }}
                    >
                      <ReactMarkdown components={markdownComponents}>{section.content}</ReactMarkdown>
                    </Box>
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Cross-Analysis Findings */}
        {selectedReport.cross_analysis_findings && selectedReport.cross_analysis_findings.length > 0 && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom>
                🔗 Cross-Domain Findings
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Vulnerabilities that span multiple scan types and domains
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.cross_analysis_findings.map((finding, idx) => (
                <Paper
                  key={idx}
                  sx={{
                    p: 2,
                    mb: 2,
                    border: `1px solid ${alpha(getRiskColor(finding.severity, theme), 0.3)}`,
                    borderLeft: `4px solid ${getRiskColor(finding.severity, theme)}`,
                  }}
                >
                  <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                    <Box sx={{ flex: 1 }}>
                      <Typography variant="h6" fontWeight={600}>
                        {finding.title}
                      </Typography>
                      <Stack direction="row" spacing={0.5} sx={{ mt: 1, mb: 2, flexWrap: "wrap", gap: 0.5 }}>
                        <Chip
                          label={finding.severity}
                          size="small"
                          sx={{
                            bgcolor: alpha(getRiskColor(finding.severity, theme), 0.15),
                            color: getRiskColor(finding.severity, theme),
                          }}
                        />
                        {finding.sources.map((source) => (
                          <Chip key={source} label={source.replace("_", " ")} size="small" variant="outlined" />
                        ))}
                        {finding.exploitability_score != null && (
                          <Chip
                            label={`Exploitability: ${(finding.exploitability_score * 100).toFixed(0)}%`}
                            size="small"
                            color={finding.exploitability_score > 0.7 ? "error" : "default"}
                            variant="outlined"
                          />
                        )}
                      </Stack>
                      <Typography sx={{ mb: 2, lineHeight: 1.7 }}>{finding.description}</Typography>
                      
                      {finding.exploit_narrative && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" fontWeight={600} color="warning.main">
                            📖 Exploit Narrative
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 1, pl: 2, borderLeft: `3px solid ${theme.palette.warning.main}`, lineHeight: 1.7 }}>
                            {finding.exploit_narrative}
                          </Typography>
                        </Box>
                      )}
                      
                      {finding.exploit_guidance && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="subtitle2" fontWeight={600} color="error.main">
                            🎯 Exploit Commands
                          </Typography>
                          <SyntaxHighlighter
                            language="bash"
                            style={vscDarkPlus}
                            customStyle={{
                              borderRadius: "8px",
                              fontSize: "0.85rem",
                              marginTop: "8px",
                              border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
                            }}
                          >
                            {finding.exploit_guidance}
                          </SyntaxHighlighter>
                        </Box>
                      )}
                      
                      {finding.remediation && (
                        <Alert severity="success" sx={{ mt: 2 }} icon={<>🛡️</>}>
                          <AlertTitle sx={{ fontWeight: 700 }}>Remediation</AlertTitle>
                          <Box sx={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</Box>
                        </Alert>
                      )}
                    </Box>
                  </Stack>
                </Paper>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Attack Surface Diagram */}
        {selectedReport.attack_surface_diagram && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom>
                🗺️ Attack Surface Map
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Box sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 2, borderRadius: 2 }}>
                <MermaidDiagram code={selectedReport.attack_surface_diagram} title="Attack Surface Map" />
              </Box>
            </CardContent>
          </Card>
        )}

        {/* Exploit Development Areas */}
        {selectedReport.exploit_development_areas && selectedReport.exploit_development_areas.length > 0 && (
          <Card sx={{ mb: 3, border: `1px solid ${alpha(theme.palette.error.main, 0.3)}` }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ color: 'error.main' }}>
                💉 Exploit Development Opportunities
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Areas recommended for security researchers to develop proof-of-concept exploits
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Grid container spacing={2}>
                {selectedReport.exploit_development_areas.map((area, idx) => (
                  <Grid item xs={12} md={6} key={idx}>
                    <Paper
                      sx={{
                        p: 2,
                        height: "100%",
                        display: "flex",
                        flexDirection: "column",
                        background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.05)} 0%, ${alpha(theme.palette.warning.main, 0.02)} 100%)`,
                        border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                      }}
                    >
                      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                        <ExploitIcon />
                        <Typography variant="h6" fontWeight={600}>
                          {area.title}
                        </Typography>
                      </Stack>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mb: 2 }}>
                        <Chip label={`Vector: ${area.attack_vector}`} size="small" variant="outlined" />
                        <Chip label={`Complexity: ${area.complexity}`} size="small" variant="outlined" />
                      </Box>
                      <Typography variant="body2" sx={{ mb: 2, flex: 1 }}>
                        {area.description}
                      </Typography>
                      {area.vulnerability_chain && area.vulnerability_chain.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" fontWeight={600}>
                            Vulnerability Chain:
                          </Typography>
                          <Stack direction="row" spacing={0.5} sx={{ mt: 0.5, flexWrap: "wrap", gap: 0.5 }}>
                            {area.vulnerability_chain.map((v, i) => (
                              <Chip key={i} label={v} size="small" color="warning" variant="outlined" />
                            ))}
                          </Stack>
                        </Box>
                      )}
                      {area.prerequisites && area.prerequisites.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" fontWeight={600}>
                            Prerequisites:
                          </Typography>
                          <ul style={{ margin: "4px 0 0 16px", padding: 0 }}>
                            {area.prerequisites.map((p, i) => (
                              <li key={i}>
                                <Typography variant="caption">{p}</Typography>
                              </li>
                            ))}
                          </ul>
                        </Box>
                      )}
                      {area.poc_guidance && (
                        <Box
                          sx={{
                            p: 1.5,
                            bgcolor: alpha(theme.palette.background.paper, 0.5),
                            borderRadius: 1,
                            border: `1px dashed ${alpha(theme.palette.error.main, 0.3)}`,
                          }}
                        >
                          <Typography variant="caption" fontWeight={600} color="error.main">
                            POC Guidance:
                          </Typography>
                          <Typography variant="caption" sx={{ display: "block", mt: 0.5 }}>
                            {area.poc_guidance}
                          </Typography>
                        </Box>
                      )}
                      <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                        <strong>Impact:</strong> {area.impact}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </CardContent>
          </Card>
        )}

        {/* Prioritized Vulnerabilities */}
        {selectedReport.prioritized_vulnerabilities && selectedReport.prioritized_vulnerabilities.length > 0 && (
          <Card sx={{ mb: 3, border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}` }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ color: 'warning.main' }}>
                📊 Prioritized Vulnerabilities
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Vulnerabilities ranked by severity, exploitability, and business impact
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.prioritized_vulnerabilities.map((vuln: any, idx) => (
                <Accordion key={idx} sx={{ mb: 1, '&:before': { display: 'none' }, border: `1px solid ${alpha(getRiskColor(vuln.severity || "medium", theme), 0.3)}`, borderRadius: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                      <Box
                        sx={{
                          width: 40,
                          height: 40,
                          borderRadius: "50%",
                          bgcolor: alpha(getRiskColor(vuln.severity || "medium", theme), 0.15),
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontWeight: 800,
                          fontSize: "1.1rem",
                          color: getRiskColor(vuln.severity || "medium", theme),
                        }}
                      >
                        #{vuln.rank || idx + 1}
                      </Box>
                      <Box sx={{ flex: 1 }}>
                        <Typography fontWeight={600}>{vuln.title}</Typography>
                        <Stack direction="row" spacing={0.5} sx={{ mt: 0.5, flexWrap: 'wrap', gap: 0.5 }}>
                          {vuln.severity && (
                            <Chip
                              label={vuln.severity}
                              size="small"
                              sx={{
                                bgcolor: alpha(getRiskColor(vuln.severity, theme), 0.15),
                                color: getRiskColor(vuln.severity, theme),
                                fontWeight: 700,
                              }}
                            />
                          )}
                          {vuln.cvss_estimate && (
                            <Chip label={`CVSS: ${vuln.cvss_estimate}`} size="small" color="error" variant="outlined" />
                          )}
                          {vuln.exploitability && (
                            <Chip label={`Exploit: ${vuln.exploitability}`} size="small" variant="outlined" color={vuln.exploitability === "Easy" ? "error" : "warning"} />
                          )}
                          {vuln.source && (
                            <Chip label={vuln.source} size="small" variant="outlined" />
                          )}
                        </Stack>
                      </Box>
                      {vuln.remediation_priority && (
                        <Chip
                          label={vuln.remediation_priority}
                          size="small"
                          color={vuln.remediation_priority === "Immediate" ? "error" : vuln.remediation_priority === "Short-term" ? "warning" : "default"}
                          sx={{ fontWeight: 600 }}
                        />
                      )}
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {vuln.impact && (
                      <Alert severity="error" sx={{ mb: 2 }} icon={<>💥</>}>
                        <AlertTitle sx={{ fontWeight: 700 }}>Business Impact</AlertTitle>
                        {vuln.impact}
                      </Alert>
                    )}
                    
                    {vuln.affected_component && (
                      <Typography variant="body2" sx={{ mb: 2, fontFamily: "'Fira Code', monospace", bgcolor: 'rgba(0,0,0,0.2)', p: 1, borderRadius: 1 }}>
                        📁 {vuln.affected_component}
                      </Typography>
                    )}
                    
                    {vuln.exploitation_steps && vuln.exploitation_steps.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, color: 'error.main' }}>
                          🎯 Exploitation Steps:
                        </Typography>
                        <Box sx={{ pl: 1 }}>
                          {vuln.exploitation_steps.map((step: string, sidx: number) => (
                            <Paper key={sidx} sx={{ p: 1.5, mb: 1, bgcolor: alpha(theme.palette.error.main, 0.05), borderLeft: `3px solid ${theme.palette.error.main}`, borderRadius: '0 8px 8px 0' }}>
                              <Typography variant="body2" sx={{ fontFamily: step.includes('curl') || step.includes('python') || step.includes('$') ? "'Fira Code', monospace" : 'inherit' }}>
                                {step}
                              </Typography>
                            </Paper>
                          ))}
                        </Box>
                      </Box>
                    )}
                    
                    {vuln.remediation_steps && vuln.remediation_steps.length > 0 && (
                      <Alert severity="success" icon={<>🛡️</>}>
                        <AlertTitle sx={{ fontWeight: 700 }}>Remediation Steps</AlertTitle>
                        <ol style={{ margin: 0, paddingLeft: 20 }}>
                          {vuln.remediation_steps.map((step: string, sidx: number) => (
                            <li key={sidx} style={{ marginBottom: 4 }}>{step}</li>
                          ))}
                        </ol>
                      </Alert>
                    )}
                    
                    {vuln.references && vuln.references.length > 0 && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="caption" color="text.secondary">
                          References: {vuln.references.join(', ')}
                        </Typography>
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Source Code Findings - Deep Dive Analysis */}
        {selectedReport.source_code_findings && selectedReport.source_code_findings.length > 0 && (
          <Card sx={{ mb: 3, border: `1px solid ${alpha(theme.palette.primary.main, 0.3)}` }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'primary.main' }}>
                <CodeIcon />
                🔍 Source Code Deep Dive Findings
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Additional vulnerabilities discovered by analyzing project source code based on scan findings
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.source_code_findings.map((finding: any, idx) => (
                <Accordion key={idx} sx={{ mb: 1, '&:before': { display: 'none' }, border: `1px solid ${alpha(getRiskColor(finding.severity, theme), 0.3)}`, borderRadius: 2 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                      <Chip
                        label={finding.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getRiskColor(finding.severity, theme), 0.15),
                          color: getRiskColor(finding.severity, theme),
                          fontWeight: 700,
                        }}
                      />
                      <Box sx={{ flex: 1 }}>
                        <Typography fontWeight={600}>{finding.issue_type}</Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "'Fira Code', monospace" }}>
                          📁 {finding.file_path} {finding.line_numbers && `(Lines ${finding.line_numbers})`}
                        </Typography>
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ mb: 2, lineHeight: 1.7 }}>
                      {finding.description}
                    </Typography>
                    
                    {finding.code_snippet && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, color: 'warning.main' }}>
                          ⚠️ Vulnerable Code:
                        </Typography>
                        <SyntaxHighlighter
                          language={finding.file_path?.endsWith('.py') ? 'python' : finding.file_path?.endsWith('.js') ? 'javascript' : finding.file_path?.endsWith('.php') ? 'php' : 'text'}
                          style={vscDarkPlus}
                          customStyle={{
                            borderRadius: "8px",
                            fontSize: "0.85rem",
                            maxHeight: "350px",
                            overflow: "auto",
                            border: `2px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                          }}
                          showLineNumbers
                        >
                          {finding.code_snippet}
                        </SyntaxHighlighter>
                      </Box>
                    )}
                    
                    {finding.related_scan_findings && finding.related_scan_findings.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600 }}>🔗 Related Scan Findings:</Typography>
                        <Stack direction="row" flexWrap="wrap" gap={0.5}>
                          {finding.related_scan_findings.map((rel: string, ridx: number) => (
                            <Chip key={ridx} label={rel} size="small" variant="outlined" color="warning" />
                          ))}
                        </Stack>
                      </Box>
                    )}
                    
                    {finding.secure_code_fix && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, color: 'success.main' }}>
                          ✅ Secure Code Fix:
                        </Typography>
                        <SyntaxHighlighter
                          language={finding.file_path?.endsWith('.py') ? 'python' : finding.file_path?.endsWith('.js') ? 'javascript' : finding.file_path?.endsWith('.php') ? 'php' : 'text'}
                          style={vscDarkPlus}
                          customStyle={{
                            borderRadius: "8px",
                            fontSize: "0.85rem",
                            maxHeight: "350px",
                            overflow: "auto",
                            border: `2px solid ${alpha(theme.palette.success.main, 0.3)}`,
                          }}
                          showLineNumbers
                        >
                          {finding.secure_code_fix}
                        </SyntaxHighlighter>
                      </Box>
                    )}
                    
                    {finding.exploitation_example && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600, color: 'error.main' }}>
                          🎯 Exploitation Example:
                        </Typography>
                        <SyntaxHighlighter
                          language="bash"
                          style={vscDarkPlus}
                          customStyle={{
                            borderRadius: "8px",
                            fontSize: "0.85rem",
                            maxHeight: "350px",
                            overflow: "auto",
                            border: `2px solid ${alpha(theme.palette.error.main, 0.3)}`,
                          }}
                        >
                          {finding.exploitation_example}
                        </SyntaxHighlighter>
                      </Box>
                    )}
                    
                    {finding.remediation && (
                      <Alert severity="info" sx={{ mt: 1 }} icon={<>🛡️</>}>
                        <AlertTitle sx={{ fontWeight: 700 }}>Remediation Steps</AlertTitle>
                        <Box sx={{ whiteSpace: 'pre-wrap' }}>{finding.remediation}</Box>
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Proof of Concept Scripts */}
        {selectedReport.poc_scripts && selectedReport.poc_scripts.length > 0 && (
          <Card sx={{ mb: 3, border: `2px solid ${theme.palette.error.main}` }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'error.main' }}>
                🔥 Proof of Concept Scripts
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Working exploit scripts ready to test vulnerabilities
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.poc_scripts.map((poc: any, idx: number) => (
                <Accordion key={idx} sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                      <Chip label={poc.language} size="small" color="primary" />
                      <Typography fontWeight={600}>{poc.vulnerability_name}</Typography>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Typography variant="body2" sx={{ mb: 2 }}>
                      {poc.description}
                    </Typography>
                    
                    {poc.usage_instructions && (
                      <Alert severity="info" sx={{ mb: 2 }}>
                        <AlertTitle>How to Use</AlertTitle>
                        <Box sx={{ fontFamily: "'Fira Code', monospace", whiteSpace: 'pre-wrap', fontSize: '0.85rem' }}>
                          {poc.usage_instructions}
                        </Box>
                      </Alert>
                    )}
                    
                    <Typography variant="subtitle2" gutterBottom sx={{ color: 'error.main', fontWeight: 600 }}>
                      📝 Script Code:
                    </Typography>
                    <SyntaxHighlighter
                      language={poc.language?.toLowerCase() || "python"}
                      style={vscDarkPlus}
                      customStyle={{
                        borderRadius: "8px",
                        fontSize: "0.85rem",
                        maxHeight: "600px",
                        overflow: "auto",
                        marginBottom: "16px",
                      }}
                      showLineNumbers
                      wrapLines
                    >
                      {poc.script_code || ""}
                    </SyntaxHighlighter>
                    
                    {poc.expected_output && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ color: 'success.main', fontWeight: 600 }}>
                          ✅ Expected Output:
                        </Typography>
                        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.1), fontFamily: "'Fira Code', monospace", fontSize: '0.85rem', whiteSpace: 'pre-wrap', borderRadius: 2, border: `1px solid ${alpha(theme.palette.success.main, 0.3)}` }}>
                          {poc.expected_output}
                        </Paper>
                      </Box>
                    )}
                    
                    {poc.customization_notes && (
                      <Alert severity="warning">
                        <AlertTitle>Customization Notes</AlertTitle>
                        {poc.customization_notes}
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Beginner Attack Guides */}
        {selectedReport.beginner_attack_guide && selectedReport.beginner_attack_guide.length > 0 && (
          <Card sx={{ mb: 3, border: `2px solid ${theme.palette.warning.main}` }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'warning.main' }}>
                📚 Beginner Attack Guides
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Step-by-step guides for exploiting vulnerabilities - written for beginners
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.beginner_attack_guide.map((guide: any, idx: number) => (
                <Accordion key={idx} sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                      <Chip 
                        label={guide.difficulty_level} 
                        size="small" 
                        color={guide.difficulty_level === 'Beginner' ? 'success' : guide.difficulty_level === 'Intermediate' ? 'warning' : 'error'} 
                      />
                      <Box sx={{ flex: 1 }}>
                        <Typography fontWeight={600}>{guide.attack_name}</Typography>
                        {guide.estimated_time && (
                          <Typography variant="caption" color="text.secondary">
                            Estimated time: {guide.estimated_time}
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {guide.prerequisites && guide.prerequisites.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600 }}>📋 Prerequisites:</Typography>
                        <Stack direction="row" flexWrap="wrap" gap={0.5}>
                          {guide.prerequisites.map((prereq: string, pidx: number) => (
                            <Chip key={pidx} label={prereq} size="small" variant="outlined" color="primary" />
                          ))}
                        </Stack>
                      </Box>
                    )}
                    
                    {guide.tools_needed && guide.tools_needed.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600 }}>🔧 Tools Needed:</Typography>
                        {guide.tools_needed.map((tool: any, tidx: number) => (
                          <Paper key={tidx} sx={{ p: 1.5, mb: 1, bgcolor: alpha(theme.palette.info.main, 0.08), border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`, borderRadius: 2 }}>
                            <Typography fontWeight={600} color="info.main">{tool.tool}</Typography>
                            {tool.installation && (
                              <Box sx={{ mt: 0.5, p: 1, bgcolor: 'rgba(0,0,0,0.3)', borderRadius: 1 }}>
                                <Typography variant="body2" sx={{ fontFamily: "'Fira Code', monospace", color: 'success.light', fontSize: '0.8rem' }}>
                                  $ {tool.installation}
                                </Typography>
                              </Box>
                            )}
                            {tool.purpose && (
                              <Typography variant="body2" sx={{ mt: 0.5, color: 'text.secondary' }}>{tool.purpose}</Typography>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    )}
                    
                    {guide.step_by_step_guide && guide.step_by_step_guide.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        <Typography variant="subtitle2" gutterBottom sx={{ fontWeight: 600 }}>📖 Step-by-Step Guide:</Typography>
                        {guide.step_by_step_guide.map((step: any, sidx: number) => (
                          <Paper key={sidx} sx={{ p: 2, mb: 1.5, borderLeft: `4px solid ${theme.palette.warning.main}`, bgcolor: alpha(theme.palette.background.paper, 0.5), borderRadius: '0 8px 8px 0' }}>
                            <Typography variant="subtitle1" fontWeight={700} sx={{ color: 'warning.main', mb: 1 }}>
                              Step {step.step_number}: {step.title}
                            </Typography>
                            <Typography variant="body2" sx={{ mb: 1.5, lineHeight: 1.6 }}>
                              {step.explanation}
                            </Typography>
                            {step.command_or_action && (
                              <SyntaxHighlighter
                                language="bash"
                                style={vscDarkPlus}
                                customStyle={{
                                  borderRadius: "6px",
                                  fontSize: "0.85rem",
                                  margin: "8px 0",
                                  padding: "12px",
                                }}
                              >
                                {step.command_or_action}
                              </SyntaxHighlighter>
                            )}
                            {step.expected_output && (
                              <Box sx={{ mt: 1.5, p: 1.5, bgcolor: alpha(theme.palette.success.main, 0.1), borderRadius: 1, border: `1px solid ${alpha(theme.palette.success.main, 0.3)}` }}>
                                <Typography variant="caption" color="success.main" fontWeight={600}>✓ Expected output:</Typography>
                                <Typography variant="body2" sx={{ fontFamily: "'Fira Code', monospace", color: 'success.light', fontSize: '0.8rem', mt: 0.5 }}>
                                  {step.expected_output}
                                </Typography>
                              </Box>
                            )}
                            {step.troubleshooting && (
                              <Alert severity="warning" sx={{ mt: 1.5 }} icon={<>⚠️</>}>
                                <Typography variant="body2" fontWeight={500}>{step.troubleshooting}</Typography>
                              </Alert>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    )}
                    
                    {guide.success_indicators && guide.success_indicators.length > 0 && (
                      <Alert severity="success" sx={{ mb: 2 }} icon={<>🎯</>}>
                        <AlertTitle sx={{ fontWeight: 700 }}>Success Indicators</AlertTitle>
                        <ul style={{ margin: 0, paddingLeft: 20 }}>
                          {guide.success_indicators.map((indicator: string, iidx: number) => (
                            <li key={iidx} style={{ marginBottom: 4 }}>{indicator}</li>
                          ))}
                        </ul>
                      </Alert>
                    )}
                    
                    {guide.what_you_can_do_after && (
                      <Alert severity="info" icon={<>🚀</>}>
                        <AlertTitle sx={{ fontWeight: 700 }}>What You Can Do After</AlertTitle>
                        {guide.what_you_can_do_after}
                      </Alert>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Attack Chains */}
        {selectedReport.attack_chains && selectedReport.attack_chains.length > 0 && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                ⛓️ Attack Chains
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Multi-step exploitation paths showing how vulnerabilities can be chained together
              </Typography>
              <Divider sx={{ my: 2 }} />
              {selectedReport.attack_chains.map((chain: any, idx: number) => (
                <Accordion key={idx} sx={{ mb: 1 }}>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, width: '100%' }}>
                      {chain.likelihood && (
                        <Chip 
                          label={chain.likelihood} 
                          size="small" 
                          color={chain.likelihood === 'High' ? 'error' : chain.likelihood === 'Medium' ? 'warning' : 'default'} 
                        />
                      )}
                      <Box sx={{ flex: 1 }}>
                        <Typography fontWeight={600}>{chain.chain_name}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Entry: {chain.entry_point}
                        </Typography>
                      </Box>
                    </Box>
                  </AccordionSummary>
                  <AccordionDetails>
                    {chain.steps && chain.steps.length > 0 && (
                      <Box sx={{ mb: 2 }}>
                        {chain.steps.map((step: any, sidx: number) => (
                          <Paper key={sidx} sx={{ p: 2, mb: 1, borderLeft: `4px solid ${theme.palette.error.main}` }}>
                            <Typography variant="subtitle2" sx={{ color: 'error.main' }}>
                              Step {step.step}
                            </Typography>
                            <Typography fontWeight={600}>{step.action}</Typography>
                            {step.vulnerability_used && (
                              <Chip label={step.vulnerability_used} size="small" variant="outlined" sx={{ mt: 0.5, mr: 1 }} />
                            )}
                            {step.outcome && (
                              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                                → {step.outcome}
                              </Typography>
                            )}
                          </Paper>
                        ))}
                      </Box>
                    )}
                    
                    {chain.final_impact && (
                      <Alert severity="error">
                        <AlertTitle>Final Impact</AlertTitle>
                        {chain.final_impact}
                      </Alert>
                    )}
                    
                    {chain.diagram && (
                      <Box sx={{ mt: 2 }}>
                        <Typography variant="subtitle2" gutterBottom>Attack Chain Diagram:</Typography>
                        <MermaidDiagram code={chain.diagram} />
                      </Box>
                    )}
                  </AccordionDetails>
                </Accordion>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Documentation Analysis */}
        {selectedReport.documentation_analysis && (
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                📄 Documentation Analysis
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Analysis of user-provided supporting documentation and how it relates to findings
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Box
                sx={{
                  "& pre": {
                    bgcolor: "rgba(0, 0, 0, 0.4) !important",
                    borderRadius: 2,
                    p: 2,
                    overflow: "auto",
                    "& code": {
                      color: "success.light",
                      fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
                      fontSize: "0.85rem",
                    },
                  },
                }}
              >
                <ReactMarkdown components={markdownComponents}>{selectedReport.documentation_analysis}</ReactMarkdown>
              </Box>
            </CardContent>
          </Card>
        )}
      </Box>
    );
  };

  return (
    <Box sx={{ maxWidth: 1400, mx: "auto", p: 3 }}>
      {/* Header */}
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 4 }}>
        <IconButton onClick={() => navigate(`/projects/${projectId}`)}>
          <BackIcon />
        </IconButton>
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
          <ReportIcon />
        </Box>
        <Box>
          <Typography variant="h4" fontWeight={700}>
            Combined Analysis Report
          </Typography>
          <Typography color="text.secondary">
            Cross-domain security analysis across all scans for{" "}
            {availableScansQuery.data?.project_name || "Project"}
          </Typography>
        </Box>
      </Stack>

      {/* Tabs */}
      <Tabs
        value={activeTab}
        onChange={(_, v) => setActiveTab(v)}
        sx={{
          mb: 3,
          "& .MuiTab-root": {
            textTransform: "none",
            fontWeight: 600,
          },
        }}
      >
        <Tab label="Create New Report" />
        <Tab label={`Previous Reports (${existingReportsQuery.data?.total || 0})`} />
        {selectedReport && <Tab label="View Report" />}
      </Tabs>

      {/* Tab Panels */}
      <TabPanel value={activeTab} index={0}>
        {/* Loading state */}
        {availableScansQuery.isLoading && (
          <Box sx={{ textAlign: "center", py: 6 }}>
            <CircularProgress size={40} />
            <Typography color="text.secondary" sx={{ mt: 2 }}>
              Loading available scans...
            </Typography>
          </Box>
        )}

        {/* Error state */}
        {availableScansQuery.isError && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {(availableScansQuery.error as Error).message}
          </Alert>
        )}

        {/* No scans available */}
        {availableScansQuery.data && availableScansQuery.data.total_available === 0 && (
          <Paper sx={{ p: 6, textAlign: "center" }}>
            <Typography variant="h6" gutterBottom>
              No Scans Available
            </Typography>
            <Typography color="text.secondary">
              Run some security scans, network analysis, or reverse engineering first.
            </Typography>
            <Button
              variant="contained"
              onClick={() => navigate(`/projects/${projectId}`)}
              sx={{ mt: 3 }}
            >
              Go to Project
            </Button>
          </Paper>
        )}

        {/* Main form */}
        {availableScansQuery.data && availableScansQuery.data.total_available > 0 && (
          <Grid container spacing={3}>
            {/* Left column - Scan selection */}
            <Grid item xs={12} lg={8}>
              <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>
                1. Select Scans to Analyze
              </Typography>

              {renderScanCategory(
                "Security Scans",
                <SecurityIcon />,
                availableScansQuery.data.security_scans,
                "security_scan",
                theme.palette.error.main
              )}

              {renderScanCategory(
                "Network Analysis",
                <NetworkIcon />,
                availableScansQuery.data.network_reports,
                "network_report",
                theme.palette.info.main
              )}

              {renderScanCategory(
                "SSL/TLS Scans",
                <SSLIcon />,
                availableScansQuery.data.ssl_scans || [],
                "ssl_scan",
                "#22c55e"
              )}

              {renderScanCategory(
                "DNS Reconnaissance",
                <DnsIcon />,
                availableScansQuery.data.dns_scans || [],
                "dns_scan",
                "#06b6d4"
              )}

              {renderScanCategory(
                "Traceroute Analysis",
                <TracerouteIcon />,
                availableScansQuery.data.traceroute_scans || [],
                "traceroute_scan",
                "#8b5cf6"
              )}

              {renderScanCategory(
                "Reverse Engineering",
                <REIcon />,
                availableScansQuery.data.re_reports,
                "re_report",
                theme.palette.warning.main
              )}

              {renderScanCategory(
                "Fuzzing Sessions",
                <FuzzIcon />,
                availableScansQuery.data.fuzzing_sessions,
                "fuzzing_session",
                theme.palette.secondary.main
              )}
            </Grid>

            {/* Right column - Config & Generate */}
            <Grid item xs={12} lg={4}>
              <Paper
                sx={{
                  p: 3,
                  position: "sticky",
                  top: 20,
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <Typography variant="h6" fontWeight={600} sx={{ mb: 3 }}>
                  2. Configure Report
                </Typography>

                {/* Report Title */}
                <TextField
                  fullWidth
                  label="Report Title"
                  value={reportTitle}
                  onChange={(e) => setReportTitle(e.target.value)}
                  placeholder="e.g., Q4 Security Assessment"
                  sx={{ mb: 2 }}
                  required
                />

                {/* Project Info */}
                <TextField
                  fullWidth
                  label="Project Info (Optional)"
                  value={projectInfo}
                  onChange={(e) => setProjectInfo(e.target.value)}
                  multiline
                  rows={3}
                  placeholder="Paste any project context, architecture notes, or background info..."
                  sx={{ mb: 2 }}
                />

                {/* User Requirements */}
                <TextField
                  fullWidth
                  label="Report Requirements (Optional)"
                  value={userRequirements}
                  onChange={(e) => setUserRequirements(e.target.value)}
                  multiline
                  rows={3}
                  placeholder="Specify what you want from this report, focus areas, specific concerns..."
                  sx={{ mb: 2 }}
                />

                {/* Supporting Documents */}
                <Box sx={{ mb: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Supporting Documents
                  </Typography>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    multiple
                    accept=".txt,.md,.pdf,.json,.yaml,.yml"
                    style={{ display: "none" }}
                  />
                  <Button
                    variant="outlined"
                    startIcon={<UploadIcon />}
                    onClick={() => fileInputRef.current?.click()}
                    fullWidth
                    sx={{ mb: 1 }}
                  >
                    Upload Documents
                  </Button>
                  {supportingDocs.length > 0 && (
                    <Stack spacing={0.5}>
                      {supportingDocs.map((doc, idx) => (
                        <Chip
                          key={idx}
                          label={doc.filename}
                          size="small"
                          onDelete={() => setSupportingDocs((prev) => prev.filter((_, i) => i !== idx))}
                        />
                      ))}
                    </Stack>
                  )}
                </Box>

                <Divider sx={{ my: 2 }} />

                {/* Options */}
                <Typography variant="subtitle2" gutterBottom>
                  Report Options
                </Typography>
                <FormControlLabel
                  control={
                    <Switch
                      checked={includeExploits}
                      onChange={(e) => setIncludeExploits(e.target.checked)}
                      size="small"
                    />
                  }
                  label="Include Exploit Recommendations"
                  sx={{ display: "block", mb: 1 }}
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={includeAttackSurface}
                      onChange={(e) => setIncludeAttackSurface(e.target.checked)}
                      size="small"
                    />
                  }
                  label="Generate Attack Surface Map"
                  sx={{ display: "block", mb: 1 }}
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={includeRiskPriority}
                      onChange={(e) => setIncludeRiskPriority(e.target.checked)}
                      size="small"
                    />
                  }
                  label="Prioritize by Exploitability"
                  sx={{ display: "block", mb: 2 }}
                />

                <Divider sx={{ my: 2 }} />

                {/* Selection Summary */}
                <Box sx={{ mb: 2, p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05), borderRadius: 1 }}>
                  <Typography variant="subtitle2" fontWeight={600}>
                    Selected: {selectedScans.length} scans
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {selectedScans.filter((s) => s.scan_type === "security_scan").length} security,{" "}
                    {selectedScans.filter((s) => s.scan_type === "network_report").length} network,{" "}
                    {selectedScans.filter((s) => s.scan_type === "re_report").length} RE,{" "}
                    {selectedScans.filter((s) => s.scan_type === "fuzzing_session").length} fuzzing
                  </Typography>
                </Box>

                {/* Generate Button */}
                <Button
                  variant="contained"
                  size="large"
                  fullWidth
                  onClick={handleGenerate}
                  disabled={generateMutation.isPending || selectedScans.length === 0 || !reportTitle.trim()}
                  sx={{
                    py: 1.5,
                    fontWeight: 700,
                    background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  }}
                >
                  {generateMutation.isPending ? (
                    <>
                      <CircularProgress size={20} sx={{ mr: 1, color: "white" }} />
                      Generating Analysis...
                    </>
                  ) : (
                    "Generate Combined Analysis"
                  )}
                </Button>

                {generateMutation.isError && (
                  <Alert severity="error" sx={{ mt: 2 }}>
                    {(generateMutation.error as Error).message}
                  </Alert>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}
      </TabPanel>

      <TabPanel value={activeTab} index={1}>
        {existingReportsQuery.isLoading && (
          <Box sx={{ textAlign: "center", py: 6 }}>
            <CircularProgress size={40} />
          </Box>
        )}

        {existingReportsQuery.data && existingReportsQuery.data.reports.length === 0 && (
          <Paper sx={{ p: 6, textAlign: "center" }}>
            <Typography variant="h6" gutterBottom>
              No Previous Reports
            </Typography>
            <Typography color="text.secondary">
              Generate your first combined analysis report.
            </Typography>
          </Paper>
        )}

        {existingReportsQuery.data && existingReportsQuery.data.reports.length > 0 && (
          <Grid container spacing={2}>
            {existingReportsQuery.data.reports.map((report) => (
              <Grid item xs={12} sm={6} md={4} key={report.id}>
                <Card
                  sx={{
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-4px)",
                      boxShadow: `0 8px 24px ${alpha(theme.palette.primary.main, 0.15)}`,
                    },
                  }}
                  onClick={() => handleViewReport(report.id)}
                >
                  <CardContent>
                    <Typography variant="h6" fontWeight={600} noWrap>
                      {report.title}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {new Date(report.created_at).toLocaleString()}
                    </Typography>
                    <Stack direction="row" spacing={0.5} sx={{ mt: 2 }}>
                      <Chip
                        label={report.overall_risk_level}
                        size="small"
                        sx={{
                          bgcolor: alpha(getRiskColor(report.overall_risk_level, theme), 0.15),
                          color: getRiskColor(report.overall_risk_level, theme),
                        }}
                      />
                      <Chip label={`Score: ${report.overall_risk_score}`} size="small" variant="outlined" />
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                      {report.total_findings_analyzed} findings from {report.scans_included} scans
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        )}
      </TabPanel>

      <TabPanel value={activeTab} index={2}>
        {renderReport()}
      </TabPanel>

      {/* Snackbar for notifications */}
      <Alert
        severity={snackbar.severity}
        sx={{
          position: "fixed",
          bottom: 24,
          right: 24,
          zIndex: 9999,
          display: snackbar.open ? "flex" : "none",
          boxShadow: 6,
          minWidth: 300,
        }}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        {snackbar.message}
      </Alert>
    </Box>
  );
}
