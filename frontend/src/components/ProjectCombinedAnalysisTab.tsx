import { useState, useRef, useEffect, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
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
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";
import ReactMarkdown from "react-markdown";
import Prism from "prismjs";
import "prismjs/themes/prism-tomorrow.css";
import "prismjs/components/prism-javascript";
import "prismjs/components/prism-typescript";
import "prismjs/components/prism-python";
import "prismjs/components/prism-java";
import "prismjs/components/prism-c";
import "prismjs/components/prism-cpp";
import "prismjs/components/prism-csharp";
import "prismjs/components/prism-go";
import "prismjs/components/prism-rust";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-json";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-php";
import "prismjs/components/prism-ruby";
import {
  combinedAnalysisApi,
  AvailableScanItem,
  SelectedScan,
  CombinedAnalysisReport,
  CombinedAnalysisRequest,
  SupportingDocument,
  DocumentAnalysisReport,
  apiClient,
  ReportSection,
  EvidenceCollectionGuide,
  ContextualRiskScore,
  RawAIResponseData,
  ControlBypassGuide,
  CorroboratedFinding,
  DocumentFindingSummary,
} from "../api/client";
import { MermaidDiagram } from "./MermaidDiagram";
import DeleteIcon from "@mui/icons-material/Delete";
import VisibilityIcon from "@mui/icons-material/Visibility";
import DescriptionIcon from "@mui/icons-material/Description";
import ArticleIcon from "@mui/icons-material/Article";
import PictureAsPdfIcon from "@mui/icons-material/PictureAsPdf";
import ChatIcon from "@mui/icons-material/Chat";
import SendIcon from "@mui/icons-material/Send";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import PersonIcon from "@mui/icons-material/Person";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";

// Chat message type
interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

// Language mapping for Prism
const getPrismLanguage = (language: string): string => {
  const mapping: Record<string, string> = {
    js: "javascript",
    ts: "typescript",
    py: "python",
    rb: "ruby",
    sh: "bash",
    shell: "bash",
    yml: "yaml",
    plaintext: "clike",
    text: "clike",
    "": "clike",
  };
  return mapping[language?.toLowerCase()] || language?.toLowerCase() || "clike";
};

// Syntax highlight code
const highlightCode = (code: string, language: string): string => {
  try {
    const prismLang = getPrismLanguage(language);
    if (Prism.languages[prismLang]) {
      return Prism.highlight(code, Prism.languages[prismLang], prismLang);
    }
  } catch {
    // Fallback to plain text
  }
  return code.replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

// Custom code component for ReactMarkdown with syntax highlighting and copy button
const CodeBlock = ({ className, children }: { className?: string; children?: React.ReactNode }) => {
  const [copied, setCopied] = useState(false);
  const match = /language-(\w+)/.exec(className || "");
  const language = match ? match[1] : "";
  const code = String(children).replace(/\n$/, "");
  
  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  if (!className) {
    // Inline code
    return (
      <code
        style={{
          backgroundColor: "rgba(255, 255, 255, 0.1)",
          padding: "2px 6px",
          borderRadius: "4px",
          fontFamily: "monospace",
          fontSize: "0.9em",
        }}
      >
        {children}
      </code>
    );
  }

  // Block code with syntax highlighting
  const highlighted = highlightCode(code, language);
  
  return (
    <Box
      sx={{
        position: "relative",
        my: 2,
        borderRadius: 1,
        overflow: "hidden",
      }}
    >
      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          bgcolor: "#2d2d2d",
          px: 1.5,
          py: 0.5,
          borderBottom: "1px solid rgba(255, 255, 255, 0.1)",
        }}
      >
        <Typography
          variant="caption"
          sx={{
            fontFamily: "monospace",
            color: "rgba(255, 255, 255, 0.7)",
            textTransform: "uppercase",
          }}
        >
          {language || "code"}
        </Typography>
        <IconButton
          size="small"
          onClick={handleCopy}
          sx={{
            color: copied ? "#22c55e" : "rgba(255, 255, 255, 0.7)",
            p: 0.5,
            "&:hover": { bgcolor: "rgba(255, 255, 255, 0.1)" },
          }}
        >
          {copied ? (
            <Box component="span" sx={{ display: "flex", alignItems: "center", gap: 0.5, fontSize: "0.75rem" }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
              </svg>
              Copied!
            </Box>
          ) : (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z" />
            </svg>
          )}
        </IconButton>
      </Box>
      <pre
        style={{
          margin: 0,
          padding: "16px",
          backgroundColor: "#1e1e1e",
          borderRadius: "0 0 8px 8px",
          overflow: "auto",
          maxHeight: "500px",
        }}
      >
        <code
          className={`language-${language}`}
          dangerouslySetInnerHTML={{ __html: highlighted }}
          style={{
            fontFamily: "'Fira Code', 'Monaco', 'Consolas', monospace",
            fontSize: "0.85rem",
            lineHeight: 1.6,
          }}
        />
      </pre>
    </Box>
  );
};

// Custom components for ReactMarkdown
const markdownComponents = {
  code: CodeBlock,
  h1: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="h4" fontWeight={700} sx={{ mt: 3, mb: 2 }}>{children}</Typography>
  ),
  h2: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="h5" fontWeight={600} sx={{ mt: 2.5, mb: 1.5 }}>{children}</Typography>
  ),
  h3: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="h6" fontWeight={600} sx={{ mt: 2, mb: 1 }}>{children}</Typography>
  ),
  p: ({ children }: { children?: React.ReactNode }) => (
    <Typography variant="body1" sx={{ mb: 1.5, lineHeight: 1.7 }}>{children}</Typography>
  ),
  ul: ({ children }: { children?: React.ReactNode }) => (
    <Box component="ul" sx={{ pl: 3, mb: 2 }}>{children}</Box>
  ),
  ol: ({ children }: { children?: React.ReactNode }) => (
    <Box component="ol" sx={{ pl: 3, mb: 2 }}>{children}</Box>
  ),
  li: ({ children }: { children?: React.ReactNode }) => (
    <Typography component="li" variant="body1" sx={{ mb: 0.5 }}>{children}</Typography>
  ),
  blockquote: ({ children }: { children?: React.ReactNode }) => (
    <Box
      sx={{
        borderLeft: "4px solid",
        borderColor: "primary.main",
        pl: 2,
        py: 1,
        my: 2,
        bgcolor: "rgba(255, 255, 255, 0.05)",
        borderRadius: "0 8px 8px 0",
      }}
    >
      {children}
    </Box>
  ),
  hr: () => <Divider sx={{ my: 3 }} />,
  strong: ({ children }: { children?: React.ReactNode }) => (
    <Box component="strong" sx={{ fontWeight: 700 }}>{children}</Box>
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
    <path d="M19.14 12.94c.04-.31.06-.63.06-.94 0-.31-.02-.63-.06-.94l2.03-1.58c.18-.14.23-.41.12-.61l-1.92-3.32c-.12-.22-.37-.29-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54c-.04-.24-.24-.41-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.04.31-.06.63-.06.94s.02.63.06.94l-2.03 1.58c-.18.14-.23.41-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z" />
  </svg>
);

interface ProjectCombinedAnalysisTabProps {
  projectId: string;
  projectName: string;
}

export default function ProjectCombinedAnalysisTab({ projectId, projectName }: ProjectCombinedAnalysisTabProps) {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Tab state
  const [activeTab, setActiveTab] = useState(0);

  // Form state
  const [selectedScans, setSelectedScans] = useState<SelectedScan[]>([]);
  const [projectInfo, setProjectInfo] = useState("");
  const [userRequirements, setUserRequirements] = useState("");
  const [supportingDocuments, setSupportingDocuments] = useState<SupportingDocument[]>([]);
  const [selectedDocReportIds, setSelectedDocReportIds] = useState<number[]>([]);
  const [reportOptions, setReportOptions] = useState({
    include_cve_enrichment: true,
    include_attack_surface_mapping: true,
    include_exploit_recommendations: true,
    include_remediation_priority: true,
  });

  // UI state
  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({
    security: true,
    network: true,
    reverse_engineering: true,
    fuzzing: true,
  });
  const [selectedReport, setSelectedReport] = useState<CombinedAnalysisReport | null>(null);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [reportToDelete, setReportToDelete] = useState<number | null>(null);
  const [exportLoading, setExportLoading] = useState<string | null>(null);

  // AI Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMaximized, setChatMaximized] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatSuggestions, setChatSuggestions] = useState<string[]>([]);
  const chatEndRef = useRef<HTMLDivElement>(null);

  // Parse raw_ai_response for enhanced data
  const parsedAIResponse: RawAIResponseData | null = useMemo(() => {
    if (!selectedReport?.raw_ai_response) return null;
    try {
      return JSON.parse(selectedReport.raw_ai_response) as RawAIResponseData;
    } catch {
      return null;
    }
  }, [selectedReport?.raw_ai_response]);

  const evidenceGuides = parsedAIResponse?.evidence_collection_guides || [];
  const contextualRiskScores = parsedAIResponse?.contextual_risk_scores || [];
  const controlBypassRecommendations = parsedAIResponse?.control_bypass_recommendations || [];
  const corroboratedFindings = parsedAIResponse?.corroborated_findings || [];
  const documentFindingCorrelation = parsedAIResponse?.document_finding_correlation;
  const documentStats = parsedAIResponse?.document_stats;

  // Queries
  const availableScansQuery = useQuery({
    queryKey: ["combined-analysis", "available-scans", projectId],
    queryFn: () => combinedAnalysisApi.getAvailableScans(parseInt(projectId)),
  });

  const analysisReportsQuery = useQuery<DocumentAnalysisReport[]>({
    queryKey: ["combined-analysis", "doc-analysis-reports", projectId],
    queryFn: () => apiClient.getAnalysisReports(parseInt(projectId)),
  });

  const reportsQuery = useQuery({
    queryKey: ["combined-analysis", "reports", projectId],
    queryFn: () => combinedAnalysisApi.listReports(parseInt(projectId)),
  });

  // Mutations
  const generateMutation = useMutation({
    mutationFn: (request: CombinedAnalysisRequest) =>
      combinedAnalysisApi.generateReport(parseInt(projectId), request),
    onSuccess: (report) => {
      queryClient.invalidateQueries({ queryKey: ["combined-analysis", "reports", projectId] });
      setSelectedReport(report);
      setActiveTab(2); // Switch to view tab
      // Reset form
      setSelectedScans([]);
      setProjectInfo("");
      setUserRequirements("");
      setSupportingDocuments([]);
      setSelectedDocReportIds([]);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (reportId: number) => combinedAnalysisApi.deleteReport(reportId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["combined-analysis", "reports", projectId] });
      setDeleteDialogOpen(false);
      setReportToDelete(null);
      if (selectedReport && selectedReport.id === reportToDelete) {
        setSelectedReport(null);
        setActiveTab(1);
      }
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
    } catch (error) {
      console.error("Export failed:", error);
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
    } catch (error) {
      console.error("Export failed:", error);
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
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setExportLoading(null);
    }
  };

  const handleSendToTeamChat = async () => {
    if (!selectedReport) return;
    setExportLoading("chat");
    try {
      await combinedAnalysisApi.sendToTeamChat(selectedReport.id);
    } catch (error) {
      console.error("Failed to send to project chat:", error);
    } finally {
      setExportLoading(null);
    }
  };

  // AI Chat functions
  useEffect(() => {
    // Scroll to bottom when new messages arrive
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  // Reset chat when report changes
  useEffect(() => {
    setChatMessages([]);
    setChatSuggestions([
      "What are the most critical vulnerabilities?",
      "Summarize the key findings",
      "What should I fix first?",
      "Are there any PoC scripts available?",
    ]);
  }, [selectedReport?.id]);

  const sendChatMessage = async (messageText?: string) => {
    const message = messageText || chatInput.trim();
    if (!message || chatLoading || !selectedReport) return;

    const userMessage: ChatMessage = { role: "user", content: message };
    setChatMessages((prev) => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    setChatSuggestions([]);

    try {
      const response = await combinedAnalysisApi.chat(
        selectedReport.id,
        message,
        chatMessages.slice(-10)
      );
      
      const assistantMessage: ChatMessage = { role: "assistant", content: response.response };
      setChatMessages((prev) => [...prev, assistantMessage]);
      
      if (response.suggestions) {
        setChatSuggestions(response.suggestions);
      }
    } catch (error) {
      console.error("Chat error:", error);
      const errorMessage: ChatMessage = {
        role: "assistant",
        content: "I apologize, but I encountered an error. Please try again or rephrase your question.",
      };
      setChatMessages((prev) => [...prev, errorMessage]);
      setChatSuggestions([
        "What are the key findings?",
        "What vulnerabilities were found?",
        "Explain the risk level",
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleChatKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendChatMessage();
    }
  };

  // Handlers
  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [category]: !prev[category],
    }));
  };

  const toggleScan = (scanType: SelectedScan['scan_type'], scanId: number, scanTitle: string) => {
    setSelectedScans((prev) => {
      const exists = prev.find((s) => s.scan_type === scanType && s.scan_id === scanId);
      if (exists) {
        return prev.filter((s) => !(s.scan_type === scanType && s.scan_id === scanId));
      }
      return [...prev, { scan_type: scanType, scan_id: scanId, title: scanTitle }];
    });
  };

  const isScanSelected = (scanType: string, scanId: number) => {
    return selectedScans.some((s) => s.scan_type === scanType && s.scan_id === scanId);
  };

  const selectAllInCategory = (category: string, scans: AvailableScanItem[]) => {
    // Check if all scans in this category are selected (using each scan's own scan_type)
    const allSelected = scans.every((scan) => isScanSelected(scan.scan_type, scan.scan_id));

    if (allSelected) {
      // Deselect all scans in this category
      setSelectedScans((prev) =>
        prev.filter((s) => !scans.some((scan) => scan.scan_type === s.scan_type && scan.scan_id === s.scan_id))
      );
    } else {
      // Select all scans in this category that aren't already selected
      const newSelections: SelectedScan[] = scans
        .filter((scan) => !isScanSelected(scan.scan_type, scan.scan_id))
        .map((scan) => ({
          scan_type: scan.scan_type as SelectedScan['scan_type'],
          scan_id: scan.scan_id,
          title: scan.title,
        }));
      setSelectedScans((prev) => [...prev, ...newSelections]);
    }
  };

  const getCategoryScanType = (category: string): SelectedScan['scan_type'] => {
    switch (category) {
      case "security":
        return "security_scan";
      case "network":
        return "network_report";
      case "reverse_engineering":
        return "re_report";
      case "fuzzing":
        return "fuzzing_session";
      default:
        return "security_scan";
    }
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files) return;

    for (const file of Array.from(files)) {
      const reader = new FileReader();
      reader.onload = () => {
        const base64 = (reader.result as string).split(",")[1];
        setSupportingDocuments((prev) => [
          ...prev,
          {
            filename: file.name,
            content_type: file.type,
            content_base64: base64,
          },
        ]);
      };
      reader.readAsDataURL(file);
    }
    event.target.value = "";
  };

  const removeDocument = (index: number) => {
    setSupportingDocuments((prev) => prev.filter((_, i) => i !== index));
  };

  const toggleDocReport = (reportId: number) => {
    setSelectedDocReportIds((prev) => {
      if (prev.includes(reportId)) {
        return prev.filter((id) => id !== reportId);
      }
      return [...prev, reportId];
    });
  };

  const handleGenerate = () => {
    if (selectedScans.length === 0) return;

    const request: CombinedAnalysisRequest = {
      project_id: parseInt(projectId),
      title: `Combined Analysis - ${new Date().toLocaleDateString()}`,
      selected_scans: selectedScans,
      project_info: projectInfo || undefined,
      user_requirements: userRequirements || undefined,
      supporting_documents: supportingDocuments.length > 0 ? supportingDocuments : undefined,
      document_analysis_report_ids: selectedDocReportIds.length > 0 ? selectedDocReportIds : undefined,
      include_exploit_recommendations: reportOptions.include_exploit_recommendations,
      include_attack_surface_map: reportOptions.include_attack_surface_mapping,
      include_risk_prioritization: reportOptions.include_remediation_priority,
    };

    generateMutation.mutate(request);
  };

  const viewReport = async (reportId: number) => {
    try {
      const report = await combinedAnalysisApi.getReport(reportId);
      setSelectedReport(report);
      setActiveTab(2);
    } catch (error) {
      console.error("Failed to load report:", error);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case "critical":
        return "#ef4444";
      case "high":
        return "#f97316";
      case "medium":
        return "#eab308";
      case "low":
        return "#22c55e";
      default:
        return "#6b7280";
    }
  };

  const getCategoryScans = (category: string): AvailableScanItem[] => {
    if (!availableScansQuery.data) return [];
    switch (category) {
      case "security":
        // Static Analysis: code-based security scans
        return availableScansQuery.data.security_scans || [];
      case "network":
        // Dynamic Analysis: all runtime/network security scans
        return [
          ...(availableScansQuery.data.network_reports || []),
          ...(availableScansQuery.data.ssl_scans || []),
          ...(availableScansQuery.data.dns_scans || []),
          ...(availableScansQuery.data.traceroute_scans || []),
          ...(availableScansQuery.data.nmap_scans || []),
          ...(availableScansQuery.data.pcap_reports || []),
          ...(availableScansQuery.data.api_tester_reports || []),
          ...(availableScansQuery.data.dynamic_scans || []),
          ...(availableScansQuery.data.agentic_fuzzer_reports || []),
          ...(availableScansQuery.data.mitm_analysis_reports || []),
        ];
      case "reverse_engineering":
        return availableScansQuery.data.re_reports || [];
      case "fuzzing":
        // API and binary fuzzing sessions
        return [
          ...(availableScansQuery.data.fuzzing_sessions || []),
          ...(availableScansQuery.data.binary_fuzzer_sessions || []),
        ];
      default:
        return [];
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "security":
        return <SecurityIcon />;
      case "network":
        return <NetworkIcon />;
      case "reverse_engineering":
        return <REIcon />;
      case "fuzzing":
        return <FuzzIcon />;
      default:
        return null;
    }
  };

  const getCategoryLabel = (category: string) => {
    switch (category) {
      case "security":
        return "Static Analysis Scans";
      case "network":
        return "Dynamic Analysis Scans";
      case "reverse_engineering":
        return "Reverse Engineering";
      case "fuzzing":
        return "Fuzzing Sessions";
      default:
        return category;
    }
  };

  const getCategoryColor = (category: string) => {
    switch (category) {
      case "security":
        return "#8b5cf6";
      case "network":
        return "#22d3ee";
      case "reverse_engineering":
        return "#f59e0b";
      case "fuzzing":
        return "#ef4444";
      default:
        return "#6b7280";
    }
  };

  const totalAvailableScans =
    (availableScansQuery.data?.security_scans?.length || 0) +
    (availableScansQuery.data?.network_reports?.length || 0) +
    (availableScansQuery.data?.ssl_scans?.length || 0) +
    (availableScansQuery.data?.dns_scans?.length || 0) +
    (availableScansQuery.data?.traceroute_scans?.length || 0) +
    (availableScansQuery.data?.nmap_scans?.length || 0) +
    (availableScansQuery.data?.pcap_reports?.length || 0) +
    (availableScansQuery.data?.api_tester_reports?.length || 0) +
    (availableScansQuery.data?.dynamic_scans?.length || 0) +
    (availableScansQuery.data?.agentic_fuzzer_reports?.length || 0) +
    (availableScansQuery.data?.binary_fuzzer_sessions?.length || 0) +
    (availableScansQuery.data?.mitm_analysis_reports?.length || 0) +
    (availableScansQuery.data?.re_reports?.length || 0) +
    (availableScansQuery.data?.fuzzing_sessions?.length || 0);

  return (
    <Box sx={{ animation: `${fadeIn} 0.5s ease-out` }}>
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: 3,
              background: `linear-gradient(135deg, ${alpha("#22d3ee", 0.2)} 0%, ${alpha("#8b5cf6", 0.2)} 100%)`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              color: "#22d3ee",
            }}
          >
            <DescriptionIcon sx={{ fontSize: 28 }} />
          </Box>
          <Box>
            <Typography variant="h4" fontWeight={700}>
              Combined Analysis Report
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Generate comprehensive analysis by combining all project scans
            </Typography>
          </Box>
        </Stack>
      </Box>

      {/* Tabs */}
      <Paper
        sx={{
          mb: 3,
          borderRadius: 2,
          background: alpha(theme.palette.background.paper, 0.6),
          backdropFilter: "blur(10px)",
        }}
      >
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          sx={{
            "& .MuiTabs-indicator": {
              height: 3,
              borderRadius: "3px 3px 0 0",
              background: `linear-gradient(90deg, #22d3ee, #8b5cf6)`,
            },
          }}
        >
          <Tab label="Create Report" />
          <Tab label={`Previous Reports (${reportsQuery.data?.reports?.length || 0})`} />
          {selectedReport && <Tab label="View Report" />}
        </Tabs>
      </Paper>

      {/* Create Report Tab */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          {/* Left Column - Scan Selection */}
          <Grid item xs={12} lg={7}>
            <Card
              sx={{
                background: alpha(theme.palette.background.paper, 0.6),
                backdropFilter: "blur(10px)",
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <CardContent>
                <Typography variant="h6" fontWeight={600} gutterBottom>
                  📊 Select Scans to Analyze
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                  Choose which scans and analysis results to include in your combined report
                </Typography>

                {availableScansQuery.isLoading && (
                  <Stack spacing={2}>
                    {[1, 2, 3, 4].map((i) => (
                      <Skeleton key={i} variant="rounded" height={80} />
                    ))}
                  </Stack>
                )}

                {availableScansQuery.isError && (
                  <Alert severity="error">Failed to load available scans</Alert>
                )}

                {availableScansQuery.data && totalAvailableScans === 0 && (
                  <Paper
                    sx={{
                      p: 4,
                      textAlign: "center",
                      background: alpha(theme.palette.info.main, 0.05),
                      border: `2px dashed ${alpha(theme.palette.info.main, 0.3)}`,
                      borderRadius: 2,
                    }}
                  >
                    <Typography variant="h6" color="text.secondary" gutterBottom>
                      No scans available yet
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Run security scans, network analysis, or reverse engineering tasks first to generate a combined report.
                    </Typography>
                  </Paper>
                )}

                {availableScansQuery.data && totalAvailableScans > 0 && (
                  <Stack spacing={2}>
                    {["security", "network", "reverse_engineering", "fuzzing"].map((category) => {
                      const scans = getCategoryScans(category);
                      if (scans.length === 0) return null;

                      const categoryColor = getCategoryColor(category);
                      // Check selection using each scan's actual scan_type
                      const allSelected = scans.every((s) =>
                        isScanSelected(s.scan_type, s.scan_id)
                      );
                      const someSelected =
                        !allSelected &&
                        scans.some((s) => isScanSelected(s.scan_type, s.scan_id));

                      return (
                        <Paper
                          key={category}
                          sx={{
                            border: `1px solid ${alpha(categoryColor, 0.3)}`,
                            borderRadius: 2,
                            overflow: "hidden",
                          }}
                        >
                          <Box
                            sx={{
                              p: 2,
                              cursor: "pointer",
                              background: alpha(categoryColor, 0.05),
                              "&:hover": {
                                background: alpha(categoryColor, 0.1),
                              },
                            }}
                            onClick={() => toggleCategory(category)}
                          >
                            <Stack direction="row" alignItems="center" justifyContent="space-between">
                              <Stack direction="row" alignItems="center" spacing={2}>
                                <Box sx={{ color: categoryColor }}>{getCategoryIcon(category)}</Box>
                                <Box>
                                  <Typography variant="subtitle1" fontWeight={600}>
                                    {getCategoryLabel(category)}
                                  </Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {scans.length} available
                                  </Typography>
                                </Box>
                              </Stack>
                              <Stack direction="row" alignItems="center" spacing={1}>
                                <Checkbox
                                  checked={allSelected}
                                  indeterminate={someSelected}
                                  onChange={(e) => {
                                    e.stopPropagation();
                                    selectAllInCategory(category, scans);
                                  }}
                                  onClick={(e) => e.stopPropagation()}
                                  sx={{
                                    color: categoryColor,
                                    "&.Mui-checked, &.MuiCheckbox-indeterminate": {
                                      color: categoryColor,
                                    },
                                  }}
                                />
                                <ExpandIcon expanded={expandedCategories[category]} />
                              </Stack>
                            </Stack>
                          </Box>

                          <Collapse in={expandedCategories[category]}>
                            <Divider />
                            <Box sx={{ p: 2 }}>
                              <Stack spacing={1}>
                                {scans.map((scan) => (
                                  <FormControlLabel
                                    key={`${scan.scan_type}-${scan.scan_id}`}
                                    control={
                                      <Checkbox
                                        checked={isScanSelected(scan.scan_type, scan.scan_id)}
                                        onChange={() =>
                                          toggleScan(scan.scan_type as SelectedScan['scan_type'], scan.scan_id, scan.title)
                                        }
                                        sx={{
                                          color: alpha(categoryColor, 0.5),
                                          "&.Mui-checked": { color: categoryColor },
                                        }}
                                      />
                                    }
                                    label={
                                      <Box>
                                        <Typography variant="body2" fontWeight={500}>
                                          {scan.title}
                                        </Typography>
                                        <Typography variant="caption" color="text.secondary">
                                          {new Date(scan.created_at).toLocaleString()}
                                          {scan.findings_count !== undefined &&
                                            ` • ${scan.findings_count} findings`}
                                          {scan.risk_level && (
                                            <Chip
                                              label={scan.risk_level}
                                              size="small"
                                              sx={{
                                                ml: 1,
                                                height: 18,
                                                fontSize: "0.65rem",
                                                bgcolor: alpha(getRiskColor(scan.risk_level), 0.1),
                                                color: getRiskColor(scan.risk_level),
                                              }}
                                            />
                                          )}
                                        </Typography>
                                      </Box>
                                    }
                                    sx={{ mx: 0, width: "100%" }}
                                  />
                                ))}
                              </Stack>
                            </Box>
                          </Collapse>
                        </Paper>
                      );
                    })}
                  </Stack>
                )}

                {selectedScans.length > 0 && (
                  <Box sx={{ mt: 3, p: 2, bgcolor: alpha("#22c55e", 0.1), borderRadius: 2 }}>
                    <Typography variant="body2" fontWeight={600} color="#22c55e">
                      ✓ {selectedScans.length} scan(s) selected for analysis
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Grid>

          {/* Right Column - Options */}
          <Grid item xs={12} lg={5}>
            <Stack spacing={3}>
              {/* Project Info */}
              <Card
                sx={{
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(10px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" fontWeight={600} gutterBottom>
                    📋 Project Information
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Paste any project context, architecture info, or background details
                  </Typography>
                  <TextField
                    multiline
                    rows={4}
                    fullWidth
                    placeholder="E.g., This is a web application using React frontend with Node.js backend..."
                    value={projectInfo}
                    onChange={(e) => setProjectInfo(e.target.value)}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        bgcolor: alpha(theme.palette.background.paper, 0.5),
                      },
                    }}
                  />
                </CardContent>
              </Card>

              {/* User Requirements */}
              <Card
                sx={{
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(10px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" fontWeight={600} gutterBottom>
                    🎯 What do you want from this report?
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Specify your focus areas, questions, or specific analysis needs
                  </Typography>
                  <TextField
                    multiline
                    rows={4}
                    fullWidth
                    placeholder="E.g., Focus on authentication vulnerabilities, identify potential privilege escalation paths..."
                    value={userRequirements}
                    onChange={(e) => setUserRequirements(e.target.value)}
                    sx={{
                      "& .MuiOutlinedInput-root": {
                        bgcolor: alpha(theme.palette.background.paper, 0.5),
                      },
                    }}
                  />
                </CardContent>
              </Card>

              {/* Supporting Documents */}
              <Card
                sx={{
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(10px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" fontWeight={600} gutterBottom>
                    📎 Supporting Documents
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Upload additional context (architecture diagrams, specs, etc.)
                  </Typography>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    multiple
                    accept=".pdf,.txt,.md,.png,.jpg,.jpeg,.json"
                    style={{ display: "none" }}
                  />
                  <Button
                    variant="outlined"
                    onClick={() => fileInputRef.current?.click()}
                    fullWidth
                    sx={{ mb: 2 }}
                  >
                    Upload Files
                  </Button>
                  {supportingDocuments.length > 0 && (
                    <Stack spacing={1}>
                      {supportingDocuments.map((doc, index) => (
                        <Chip
                          key={index}
                          label={doc.filename}
                          onDelete={() => removeDocument(index)}
                          sx={{ justifyContent: "space-between" }}
                        />
                      ))}
                    </Stack>
                  )}
                </CardContent>
              </Card>

              {/* Attach Document Analysis Reports */}
              <Card
                sx={{
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(10px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" fontWeight={600} gutterBottom>
                    🧠 AI Document Analysis Reports
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Attach existing AI document summaries instead of re-uploading files
                  </Typography>

                  {analysisReportsQuery.isLoading && (
                    <Stack spacing={1}>
                      {[1, 2].map((i) => (
                        <Skeleton key={i} variant="rectangular" height={36} sx={{ borderRadius: 1 }} />
                      ))}
                    </Stack>
                  )}

                  {analysisReportsQuery.data && analysisReportsQuery.data.length === 0 && (
                    <Alert severity="info">
                      No document analysis reports found for this project.
                    </Alert>
                  )}

                  {analysisReportsQuery.data && analysisReportsQuery.data.length > 0 && (
                    <Stack spacing={1}>
                      {analysisReportsQuery.data.map((report) => {
                        const isCompleted = report.status === "completed";
                        return (
                          <FormControlLabel
                            key={report.id}
                            control={
                              <Checkbox
                                checked={selectedDocReportIds.includes(report.id)}
                                onChange={() => toggleDocReport(report.id)}
                                disabled={!isCompleted}
                              />
                            }
                            label={
                              <Stack spacing={0.2}>
                                <Typography variant="body2" fontWeight={600}>
                                  Analysis Report #{report.id}
                                </Typography>
                                <Typography variant="caption" color="text.secondary">
                                  {report.documents?.length || 0} documents •{" "}
                                  {new Date(report.created_at).toLocaleDateString()} •{" "}
                                  {report.status}
                                </Typography>
                              </Stack>
                            }
                          />
                        );
                      })}
                    </Stack>
                  )}
                </CardContent>
              </Card>

              {/* Report Options */}
              <Card
                sx={{
                  background: alpha(theme.palette.background.paper, 0.6),
                  backdropFilter: "blur(10px)",
                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                }}
              >
                <CardContent>
                  <Typography variant="h6" fontWeight={600} gutterBottom>
                    ⚙️ Report Options
                  </Typography>
                  <Stack spacing={1}>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={reportOptions.include_cve_enrichment}
                          onChange={(e) =>
                            setReportOptions((prev) => ({
                              ...prev,
                              include_cve_enrichment: e.target.checked,
                            }))
                          }
                        />
                      }
                      label="Include CVE Enrichment"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={reportOptions.include_attack_surface_mapping}
                          onChange={(e) =>
                            setReportOptions((prev) => ({
                              ...prev,
                              include_attack_surface_mapping: e.target.checked,
                            }))
                          }
                        />
                      }
                      label="Include Attack Surface Mapping"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={reportOptions.include_exploit_recommendations}
                          onChange={(e) =>
                            setReportOptions((prev) => ({
                              ...prev,
                              include_exploit_recommendations: e.target.checked,
                            }))
                          }
                        />
                      }
                      label="Include Exploit Recommendations"
                    />
                    <FormControlLabel
                      control={
                        <Switch
                          checked={reportOptions.include_remediation_priority}
                          onChange={(e) =>
                            setReportOptions((prev) => ({
                              ...prev,
                              include_remediation_priority: e.target.checked,
                            }))
                          }
                        />
                      }
                      label="Include Remediation Priority"
                    />
                  </Stack>
                </CardContent>
              </Card>

              {/* Generate Button */}
              <Button
                variant="contained"
                size="large"
                onClick={handleGenerate}
                disabled={selectedScans.length === 0 || generateMutation.isPending}
                sx={{
                  py: 2,
                  fontSize: "1.1rem",
                  fontWeight: 700,
                  background: `linear-gradient(135deg, #22d3ee 0%, #8b5cf6 100%)`,
                  boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.4)}`,
                  "&:hover": {
                    background: `linear-gradient(135deg, #06b6d4 0%, #7c3aed 100%)`,
                    boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.5)}`,
                    transform: "translateY(-2px)",
                  },
                  "&:disabled": {
                    background: alpha(theme.palette.action.disabled, 0.3),
                  },
                  transition: "all 0.3s ease",
                }}
              >
                {generateMutation.isPending ? (
                  <Stack direction="row" alignItems="center" spacing={2}>
                    <CircularProgress size={24} color="inherit" />
                    <span>Generating Report...</span>
                  </Stack>
                ) : (
                  "🚀 Generate Combined Analysis Report"
                )}
              </Button>

              {generateMutation.isError && (
                <Alert severity="error">
                  {(generateMutation.error as Error).message || "Failed to generate report"}
                </Alert>
              )}
            </Stack>
          </Grid>
        </Grid>
      )}

      {/* Previous Reports Tab */}
      {activeTab === 1 && (
        <Card
          sx={{
            background: alpha(theme.palette.background.paper, 0.6),
            backdropFilter: "blur(10px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          }}
        >
          <CardContent>
            <Typography variant="h6" fontWeight={600} gutterBottom>
              📚 Previous Reports
            </Typography>

            {reportsQuery.isLoading && (
              <Stack spacing={2}>
                {[1, 2, 3].map((i) => (
                  <Skeleton key={i} variant="rounded" height={80} />
                ))}
              </Stack>
            )}

            {reportsQuery.isError && (
              <Alert severity="error">Failed to load reports</Alert>
            )}

            {reportsQuery.data && reportsQuery.data.reports.length === 0 && (
              <Paper
                sx={{
                  p: 4,
                  textAlign: "center",
                  background: alpha(theme.palette.info.main, 0.05),
                  border: `2px dashed ${alpha(theme.palette.info.main, 0.3)}`,
                  borderRadius: 2,
                }}
              >
                <Typography variant="h6" color="text.secondary" gutterBottom>
                  No reports generated yet
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Create your first combined analysis report to see it here.
                </Typography>
              </Paper>
            )}

            {reportsQuery.data && reportsQuery.data.reports.length > 0 && (
              <List>
                {reportsQuery.data.reports.map((report) => (
                  <Paper
                    key={report.id}
                    sx={{
                      mb: 2,
                      p: 2,
                      border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                      borderRadius: 2,
                      "&:hover": {
                        bgcolor: alpha(theme.palette.primary.main, 0.05),
                      },
                    }}
                  >
                    <Stack direction="row" justifyContent="space-between" alignItems="center">
                      <Box>
                        <Typography variant="subtitle1" fontWeight={600}>
                          {report.title}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(report.created_at).toLocaleString()} •{" "}
                          {report.scans_included} scans analyzed
                        </Typography>
                        <Box sx={{ mt: 1 }}>
                          <Chip
                            label={report.overall_risk_level}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(report.overall_risk_level), 0.1),
                              color: getRiskColor(report.overall_risk_level),
                              fontWeight: 600,
                            }}
                          />
                        </Box>
                      </Box>
                      <Stack direction="row" spacing={1}>
                        <Tooltip title="View Report">
                          <IconButton
                            onClick={() => viewReport(report.id)}
                            sx={{ color: "#22d3ee" }}
                          >
                            <VisibilityIcon />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete Report">
                          <IconButton
                            onClick={() => {
                              setReportToDelete(report.id);
                              setDeleteDialogOpen(true);
                            }}
                            sx={{ color: "#ef4444" }}
                          >
                            <DeleteIcon />
                          </IconButton>
                        </Tooltip>
                      </Stack>
                    </Stack>
                  </Paper>
                ))}
              </List>
            )}
          </CardContent>
        </Card>
      )}

      {/* View Report Tab */}
      {activeTab === 2 && selectedReport && (
        <Box sx={{ animation: `${fadeIn} 0.5s ease-out` }}>
          {/* Report Header */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                <Box>
                  <Typography variant="h5" fontWeight={700} gutterBottom>
                    {selectedReport.title}
                  </Typography>
                  <Stack direction="row" spacing={2} alignItems="center">
                    <Typography variant="body2" color="text.secondary">
                      Generated: {new Date(selectedReport.created_at).toLocaleString()}
                    </Typography>
                    <Chip
                      label={`${selectedReport.scans_included} scans analyzed`}
                      size="small"
                      variant="outlined"
                    />
                    <Chip
                      label={`${selectedReport.total_findings_analyzed} findings`}
                      size="small"
                      variant="outlined"
                    />
                  </Stack>
                </Box>
                <Box sx={{ textAlign: "right" }}>
                  <Chip
                    label={selectedReport.overall_risk_level?.toUpperCase()}
                    sx={{
                      bgcolor: alpha(getRiskColor(selectedReport.overall_risk_level), 0.1),
                      color: getRiskColor(selectedReport.overall_risk_level),
                      fontWeight: 700,
                      fontSize: "1rem",
                      px: 2,
                      py: 2.5,
                    }}
                  />
                  <Typography variant="h4" fontWeight={700} sx={{ mt: 1 }}>
                    {selectedReport.overall_risk_score}/100
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Risk Score
                  </Typography>
                </Box>
              </Stack>
              
              {/* Export & Share Section */}
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
                  <Stack direction="row" spacing={1}>
                    <Tooltip title="Send report summary to project chat">
                      <Button
                        size="small"
                        variant="contained"
                        color="primary"
                        startIcon={exportLoading === "chat" ? <CircularProgress size={16} color="inherit" /> : <ChatIcon />}
                        onClick={handleSendToTeamChat}
                        disabled={!!exportLoading}
                      >
                        Send to Chat
                      </Button>
                    </Tooltip>
                  </Stack>
                </Stack>
              </Box>
            </CardContent>
          </Card>

          {/* Executive Summary */}
          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h5" fontWeight={600} gutterBottom>
                📋 Executive Summary
              </Typography>
              <Divider sx={{ my: 2 }} />
              <Box
                sx={{
                  lineHeight: 1.8,
                  "& p": { mb: 2 },
                }}
              >
                <ReactMarkdown components={markdownComponents}>{selectedReport.executive_summary}</ReactMarkdown>
              </Box>
            </CardContent>
          </Card>

          {/* Report Sections */}
          {selectedReport.sections &&
            selectedReport.sections.map((section: ReportSection, index: number) => (
              <Accordion
                key={index}
                defaultExpanded={index < 3}
                sx={{
                  mb: 2,
                  "&:before": { display: "none" },
                  borderRadius: "8px !important",
                  overflow: "hidden",
                }}
              >
                <AccordionSummary
                  expandIcon={<ExpandIcon expanded={false} />}
                  sx={{
                    bgcolor: alpha(theme.palette.primary.main, 0.05),
                  }}
                >
                  <Typography variant="h6" fontWeight={600}>
                    {section.title}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <ReactMarkdown components={markdownComponents}>{section.content}</ReactMarkdown>
                </AccordionDetails>
              </Accordion>
            ))}

          {/* Cross-Analysis Findings */}
          {selectedReport.cross_analysis_findings &&
            selectedReport.cross_analysis_findings.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    🔗 Cross-Analysis Findings
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Vulnerabilities and patterns identified by correlating multiple scan types
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={2}>
                    {selectedReport.cross_analysis_findings.map((finding, index) => (
                      <Paper
                        key={index}
                        sx={{
                          p: 2,
                          border: `1px solid ${alpha(getRiskColor(finding.severity), 0.3)}`,
                          borderLeft: `4px solid ${getRiskColor(finding.severity)}`,
                          borderRadius: 1,
                        }}
                      >
                        <Stack
                          direction="row"
                          justifyContent="space-between"
                          alignItems="flex-start"
                        >
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle1" fontWeight={600}>
                              {finding.title}
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                              {finding.description}
                            </Typography>
                            <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
                              {finding.sources.map((source: string, i: number) => (
                                <Chip key={i} label={source} size="small" variant="outlined" />
                              ))}
                            </Stack>
                          </Box>
                          <Chip
                            label={finding.severity}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(finding.severity), 0.1),
                              color: getRiskColor(finding.severity),
                              fontWeight: 600,
                            }}
                          />
                        </Stack>
                      </Paper>
                    ))}
                  </Stack>
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
                <Box
                  sx={{ bgcolor: alpha(theme.palette.background.paper, 0.5), p: 2, borderRadius: 2 }}
                >
                  <MermaidDiagram
                    code={selectedReport.attack_surface_diagram}
                    title="Attack Surface Map"
                  />
                </Box>
              </CardContent>
            </Card>
          )}

          {/* Exploit Development Areas */}
          {selectedReport.exploit_development_areas &&
            selectedReport.exploit_development_areas.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    💉 Exploit Development Opportunities
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Areas recommended for security researchers to develop proof-of-concept exploits
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Grid container spacing={2}>
                    {selectedReport.exploit_development_areas.map((area, index) => (
                      <Grid item xs={12} md={6} key={index}>
                        <Paper
                          sx={{
                            p: 2,
                            height: "100%",
                            border: `1px solid ${alpha("#ef4444", 0.3)}`,
                            borderRadius: 2,
                            background: alpha("#ef4444", 0.02),
                            display: "flex",
                            flexDirection: "column",
                          }}
                        >
                          <Typography variant="subtitle1" fontWeight={600} color="#ef4444">
                            {area.title}
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 1, flex: 1 }}>
                            {area.description}
                          </Typography>
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="caption" color="text.secondary" fontWeight={600}>
                              Attack Vector:
                            </Typography>
                            <Typography variant="body2">{area.attack_vector}</Typography>
                          </Box>
                          <Box sx={{ mt: 2, display: "flex", flexWrap: "wrap", gap: 1 }}>
                            <Chip
                              label={`Complexity: ${area.complexity}`}
                              size="small"
                              variant="outlined"
                              sx={{ maxWidth: "100%" }}
                            />
                          </Box>
                          <Box sx={{ mt: 1.5 }}>
                            <Typography variant="caption" color="text.secondary" fontWeight={600}>
                              Impact:
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 0.5 }}>
                              {area.impact}
                            </Typography>
                          </Box>
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </CardContent>
              </Card>
            )}

          {/* Prioritized Vulnerabilities */}
          {selectedReport.prioritized_vulnerabilities &&
            selectedReport.prioritized_vulnerabilities.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    🎯 Prioritized Vulnerabilities
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ranked by exploitability, impact, and remediation complexity
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={2}>
                    {selectedReport.prioritized_vulnerabilities.map((vuln: any, index: number) => (
                      <Accordion key={index} defaultExpanded={index === 0}>
                        <AccordionSummary expandIcon={<ExpandIcon expanded={false} />}>
                          <Stack direction="row" spacing={2} alignItems="center" sx={{ width: "100%" }}>
                            <Box
                              sx={{
                                width: 40,
                                height: 40,
                                borderRadius: "50%",
                                bgcolor: alpha(getRiskColor(vuln.severity || "medium"), 0.1),
                                color: getRiskColor(vuln.severity || "medium"),
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontWeight: 700,
                              }}
                            >
                              #{vuln.rank || index + 1}
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Typography variant="subtitle1" fontWeight={600}>
                                {vuln.title || vuln.name}
                              </Typography>
                            </Box>
                            <Chip
                              label={vuln.severity || "Medium"}
                              size="small"
                              sx={{
                                bgcolor: alpha(getRiskColor(vuln.severity || "medium"), 0.1),
                                color: getRiskColor(vuln.severity || "medium"),
                                fontWeight: 600,
                              }}
                            />
                          </Stack>
                        </AccordionSummary>
                        <AccordionDetails>
                          <Stack spacing={2}>
                            {/* Impact */}
                            {vuln.impact && (
                              <Box>
                                <Typography variant="subtitle2" fontWeight={600} color="error.main" gutterBottom>
                                  💥 Impact
                                </Typography>
                                <Typography variant="body2">{vuln.impact}</Typography>
                              </Box>
                            )}
                            
                            {/* Affected Component */}
                            {vuln.affected_component && (
                              <Box>
                                <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                                  📍 Affected Component
                                </Typography>
                                <Typography variant="body2" sx={{ fontFamily: "monospace", bgcolor: alpha(theme.palette.primary.main, 0.05), p: 1, borderRadius: 1 }}>
                                  {vuln.affected_component}
                                </Typography>
                              </Box>
                            )}
                            
                            {/* Exploitation Steps */}
                            {vuln.exploitation_steps && vuln.exploitation_steps.length > 0 && (
                              <Box>
                                <Typography variant="subtitle2" fontWeight={600} color="warning.main" gutterBottom>
                                  ⚔️ Exploitation Steps
                                </Typography>
                                <Stack spacing={1}>
                                  {vuln.exploitation_steps.map((step: string, stepIdx: number) => (
                                    <Box key={stepIdx} sx={{ display: "flex", gap: 1, alignItems: "flex-start" }}>
                                      <Chip label={stepIdx + 1} size="small" sx={{ minWidth: 28, height: 24 }} />
                                      <Typography variant="body2">{step.replace(/^Step \d+:?\s*/i, "")}</Typography>
                                    </Box>
                                  ))}
                                </Stack>
                              </Box>
                            )}
                            
                            {/* Remediation Steps */}
                            {vuln.remediation_steps && vuln.remediation_steps.length > 0 && (
                              <Box>
                                <Typography variant="subtitle2" fontWeight={600} color="success.main" gutterBottom>
                                  🛡️ Remediation
                                </Typography>
                                <Stack spacing={0.5}>
                                  {vuln.remediation_steps.map((step: string, stepIdx: number) => (
                                    <Typography key={stepIdx} variant="body2">• {step}</Typography>
                                  ))}
                                </Stack>
                              </Box>
                            )}
                            
                            {/* References */}
                            {vuln.references && vuln.references.length > 0 && (
                              <Box>
                                <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                                  📚 References
                                </Typography>
                                <Stack direction="row" spacing={1} flexWrap="wrap">
                                  {vuln.references.map((ref: string, refIdx: number) => (
                                    <Chip key={refIdx} label={ref} size="small" variant="outlined" />
                                  ))}
                                </Stack>
                              </Box>
                            )}
                            
                            {/* Metadata Row */}
                            <Stack direction="row" spacing={2} flexWrap="wrap">
                              {vuln.cvss_estimate && (
                                <Chip label={`CVSS: ${vuln.cvss_estimate}`} size="small" color="error" variant="outlined" />
                              )}
                              {vuln.exploitability && (
                                <Chip label={`Exploitability: ${vuln.exploitability}`} size="small" variant="outlined" />
                              )}
                              {vuln.remediation_priority && (
                                <Chip label={`Priority: ${vuln.remediation_priority}`} size="small" color="warning" variant="outlined" />
                              )}
                            </Stack>
                          </Stack>
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}

          {/* Beginner Attack Guides */}
          {selectedReport.beginner_attack_guide &&
            selectedReport.beginner_attack_guide.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    📖 Step-by-Step Attack Guides
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Beginner-friendly exploitation guides with detailed instructions
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={3}>
                    {selectedReport.beginner_attack_guide.map((guide: any, index: number) => (
                      <Accordion key={index} defaultExpanded={index === 0}>
                        <AccordionSummary expandIcon={<ExpandIcon expanded={false} />}>
                          <Stack direction="row" alignItems="center" spacing={2} sx={{ width: "100%" }}>
                            <Box
                              sx={{
                                width: 36,
                                height: 36,
                                borderRadius: "50%",
                                bgcolor: alpha("#22c55e", 0.1),
                                color: "#22c55e",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontWeight: 700,
                                fontSize: "0.9rem",
                              }}
                            >
                              {index + 1}
                            </Box>
                            <Box sx={{ flex: 1 }}>
                              <Typography variant="subtitle1" fontWeight={600}>
                                {guide.attack_name || guide.title}
                              </Typography>
                              <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
                                {guide.difficulty_level && (
                                  <Chip label={guide.difficulty_level} size="small" variant="outlined" />
                                )}
                                {guide.estimated_time && (
                                  <Chip label={guide.estimated_time} size="small" variant="outlined" />
                                )}
                              </Stack>
                            </Box>
                          </Stack>
                        </AccordionSummary>
                        <AccordionDetails>
                          {/* Prerequisites */}
                          {guide.prerequisites && guide.prerequisites.length > 0 && (
                            <Box sx={{ mb: 3 }}>
                              <Typography variant="subtitle2" fontWeight={600} color="warning.main" sx={{ mb: 1 }}>
                                ⚠️ Prerequisites
                              </Typography>
                              <List dense>
                                {guide.prerequisites.map((prereq: string, i: number) => (
                                  <ListItem key={i} sx={{ py: 0.5 }}>
                                    <ListItemIcon sx={{ minWidth: 30 }}>•</ListItemIcon>
                                    <ListItemText primary={prereq} />
                                  </ListItem>
                                ))}
                              </List>
                            </Box>
                          )}

                          {/* Tools Needed */}
                          {guide.tools_needed && guide.tools_needed.length > 0 && (
                            <Box sx={{ mb: 3 }}>
                              <Typography variant="subtitle2" fontWeight={600} color="info.main" sx={{ mb: 1 }}>
                                🛠️ Tools Needed
                              </Typography>
                              <Stack spacing={1}>
                                {guide.tools_needed.map((tool: any, i: number) => (
                                  <Paper key={i} sx={{ p: 1.5, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                                    <Typography variant="body2" fontWeight={600}>{tool.tool}</Typography>
                                    {tool.installation && (
                                      <Typography
                                        variant="body2"
                                        sx={{ fontFamily: "monospace", fontSize: "0.8rem", mt: 0.5, color: "text.secondary" }}
                                      >
                                        Install: {tool.installation}
                                      </Typography>
                                    )}
                                    {tool.purpose && (
                                      <Typography variant="caption" color="text.secondary">{tool.purpose}</Typography>
                                    )}
                                  </Paper>
                                ))}
                              </Stack>
                            </Box>
                          )}

                          {/* Step-by-Step Guide */}
                          {guide.step_by_step_guide && guide.step_by_step_guide.length > 0 && (
                            <Box sx={{ mb: 3 }}>
                              <Typography variant="subtitle2" fontWeight={600} color="success.main" sx={{ mb: 2 }}>
                                📋 Step-by-Step Instructions
                              </Typography>
                              <Stack spacing={2}>
                                {guide.step_by_step_guide.map((step: any, i: number) => (
                                  <Paper
                                    key={i}
                                    sx={{
                                      p: 2,
                                      borderLeft: `4px solid ${alpha("#22c55e", 0.5)}`,
                                      bgcolor: alpha("#22c55e", 0.02),
                                    }}
                                  >
                                    <Typography variant="subtitle2" fontWeight={700}>
                                      Step {step.step_number || i + 1}: {step.title}
                                    </Typography>
                                    <Typography variant="body2" sx={{ mt: 1 }}>
                                      {step.explanation}
                                    </Typography>
                                    {step.command_or_action && (
                                      <Box
                                        sx={{
                                          mt: 1.5,
                                          p: 1.5,
                                          bgcolor: "#1e1e1e",
                                          borderRadius: 1,
                                          fontFamily: "monospace",
                                          fontSize: "0.85rem",
                                          color: "#22c55e",
                                          overflow: "auto",
                                        }}
                                      >
                                        <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{step.command_or_action}</pre>
                                      </Box>
                                    )}
                                    {step.expected_output && (
                                      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                                        <strong>Expected Output:</strong> {step.expected_output}
                                      </Typography>
                                    )}
                                    {step.troubleshooting && (
                                      <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 0.5 }}>
                                        <strong>Troubleshooting:</strong> {step.troubleshooting}
                                      </Typography>
                                    )}
                                  </Paper>
                                ))}
                              </Stack>
                            </Box>
                          )}

                          {/* Success Indicators */}
                          {guide.success_indicators && guide.success_indicators.length > 0 && (
                            <Box sx={{ mb: 2 }}>
                              <Typography variant="subtitle2" fontWeight={600} color="success.main" sx={{ mb: 1 }}>
                                ✅ Success Indicators
                              </Typography>
                              <List dense>
                                {guide.success_indicators.map((indicator: string, i: number) => (
                                  <ListItem key={i} sx={{ py: 0.25 }}>
                                    <ListItemIcon sx={{ minWidth: 30, color: "#22c55e" }}>✓</ListItemIcon>
                                    <ListItemText primary={indicator} />
                                  </ListItem>
                                ))}
                              </List>
                            </Box>
                          )}

                          {/* What you can do after */}
                          {guide.what_you_can_do_after && (
                            <Alert severity="info" sx={{ mt: 2 }}>
                              <Typography variant="body2">
                                <strong>After successful exploitation:</strong> {guide.what_you_can_do_after}
                              </Typography>
                            </Alert>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}

          {/* PoC Scripts */}
          {selectedReport.poc_scripts &&
            selectedReport.poc_scripts.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    🔧 Proof-of-Concept Scripts
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Working exploitation scripts with detailed comments
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={3}>
                    {selectedReport.poc_scripts.map((poc: any, index: number) => (
                      <Paper
                        key={index}
                        sx={{
                          border: `1px solid ${alpha("#f59e0b", 0.3)}`,
                          borderRadius: 2,
                          overflow: "hidden",
                        }}
                      >
                        <Box sx={{ p: 2, bgcolor: alpha("#f59e0b", 0.05) }}>
                          <Stack direction="row" justifyContent="space-between" alignItems="center">
                            <Box>
                              <Typography variant="subtitle1" fontWeight={600}>
                                {poc.vulnerability_name || poc.title}
                              </Typography>
                              <Typography variant="body2" color="text.secondary">
                                {poc.description}
                              </Typography>
                            </Box>
                            <Chip label={poc.language} size="small" sx={{ bgcolor: alpha("#f59e0b", 0.1), fontWeight: 600 }} />
                          </Stack>
                        </Box>
                        <Box
                          sx={{
                            p: 2,
                            bgcolor: "#1e1e1e",
                            fontFamily: "monospace",
                            fontSize: "0.8rem",
                            overflow: "auto",
                            maxHeight: 400,
                          }}
                        >
                          <pre style={{ margin: 0, color: "#d4d4d4", whiteSpace: "pre-wrap" }}>
                            {poc.script_code || poc.code}
                          </pre>
                        </Box>
                        {(poc.usage_instructions || poc.expected_output) && (
                          <Box sx={{ p: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                            {poc.usage_instructions && (
                              <Typography variant="body2" sx={{ mb: 1 }}>
                                <strong>Usage:</strong> {poc.usage_instructions}
                              </Typography>
                            )}
                            {poc.expected_output && (
                              <Typography variant="body2" color="text.secondary">
                                <strong>Expected Output:</strong> {poc.expected_output}
                              </Typography>
                            )}
                          </Box>
                        )}
                      </Paper>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}

          {/* Attack Chains */}
          {selectedReport.attack_chains &&
            selectedReport.attack_chains.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    ⛓️ Attack Chains
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Multi-step exploitation paths from initial access to final impact
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={3}>
                    {selectedReport.attack_chains.map((chain: any, index: number) => (
                      <Accordion key={index} defaultExpanded={index === 0}>
                        <AccordionSummary expandIcon={<ExpandIcon expanded={false} />}>
                          <Stack direction="row" alignItems="center" spacing={2}>
                            <Box
                              sx={{
                                width: 32,
                                height: 32,
                                borderRadius: 1,
                                bgcolor: alpha("#ef4444", 0.1),
                                color: "#ef4444",
                                display: "flex",
                                alignItems: "center",
                                justifyContent: "center",
                                fontWeight: 700,
                                fontSize: "0.85rem",
                              }}
                            >
                              {index + 1}
                            </Box>
                            <Box>
                              <Typography variant="subtitle1" fontWeight={600}>
                                {chain.chain_name || chain.name}
                              </Typography>
                              <Typography variant="caption" color="text.secondary">
                                Entry: {chain.entry_point} → Impact: {chain.final_impact}
                              </Typography>
                            </Box>
                            {chain.likelihood && (
                              <Chip label={`${chain.likelihood} Likelihood`} size="small" variant="outlined" />
                            )}
                          </Stack>
                        </AccordionSummary>
                        <AccordionDetails>
                          {/* Steps */}
                          {chain.steps && chain.steps.length > 0 && (
                            <Stack spacing={1} sx={{ mb: 2 }}>
                              {chain.steps.map((step: any, i: number) => (
                                <Paper
                                  key={i}
                                  sx={{
                                    p: 1.5,
                                    borderLeft: `3px solid ${alpha("#ef4444", 0.5)}`,
                                    bgcolor: alpha("#ef4444", 0.02),
                                  }}
                                >
                                  <Typography variant="body2" fontWeight={600}>
                                    Step {step.step || i + 1}: {step.action}
                                  </Typography>
                                  {step.vulnerability_used && (
                                    <Typography variant="caption" color="text.secondary">
                                      Uses: {step.vulnerability_used}
                                    </Typography>
                                  )}
                                  {step.outcome && (
                                    <Typography variant="caption" color="success.main" sx={{ display: "block" }}>
                                      Outcome: {step.outcome}
                                    </Typography>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          )}

                          {/* Chain Diagram */}
                          {chain.diagram && (
                            <Box sx={{ mt: 2, bgcolor: alpha(theme.palette.background.paper, 0.5), p: 2, borderRadius: 2 }}>
                              <MermaidDiagram code={chain.diagram} title={`Attack Chain: ${chain.chain_name}`} />
                            </Box>
                          )}
                        </AccordionDetails>
                      </Accordion>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}

          {/* Source Code Findings */}
          {selectedReport.source_code_findings &&
            selectedReport.source_code_findings.length > 0 && (
              <Card sx={{ mb: 3 }}>
                <CardContent>
                  <Typography variant="h5" fontWeight={600} gutterBottom>
                    📝 Source Code Findings
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Vulnerabilities identified in the project source code
                  </Typography>
                  <Divider sx={{ my: 2 }} />
                  <Stack spacing={2}>
                    {selectedReport.source_code_findings.map((finding: any, index: number) => (
                      <Paper
                        key={index}
                        sx={{
                          p: 2,
                          border: `1px solid ${alpha(getRiskColor(finding.severity || "medium"), 0.3)}`,
                          borderLeft: `4px solid ${getRiskColor(finding.severity || "medium")}`,
                        }}
                      >
                        <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle1" fontWeight={600}>
                              {finding.issue_type || finding.type}
                            </Typography>
                            <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace" }}>
                              {finding.file_path} {finding.line_numbers && `(Lines ${finding.line_numbers})`}
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 1 }}>
                              {finding.description}
                            </Typography>
                          </Box>
                          <Chip
                            label={finding.severity || "Medium"}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(finding.severity || "medium"), 0.1),
                              color: getRiskColor(finding.severity || "medium"),
                              fontWeight: 600,
                            }}
                          />
                        </Stack>

                        {/* Vulnerable Code */}
                        {finding.vulnerable_code_snippet && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="caption" fontWeight={600} color="error.main">
                              Vulnerable Code:
                            </Typography>
                            <Box
                              sx={{
                                mt: 0.5,
                                p: 1.5,
                                bgcolor: "#1e1e1e",
                                borderRadius: 1,
                                fontFamily: "monospace",
                                fontSize: "0.8rem",
                                color: "#f87171",
                                overflow: "auto",
                              }}
                            >
                              <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{finding.vulnerable_code_snippet}</pre>
                            </Box>
                          </Box>
                        )}

                        {/* Secure Fix */}
                        {finding.secure_code_fix && (
                          <Box sx={{ mt: 2 }}>
                            <Typography variant="caption" fontWeight={600} color="success.main">
                              Secure Fix:
                            </Typography>
                            <Box
                              sx={{
                                mt: 0.5,
                                p: 1.5,
                                bgcolor: "#1e1e1e",
                                borderRadius: 1,
                                fontFamily: "monospace",
                                fontSize: "0.8rem",
                                color: "#4ade80",
                                overflow: "auto",
                              }}
                            >
                              <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{finding.secure_code_fix}</pre>
                            </Box>
                          </Box>
                        )}

                        {/* Exploitation Example */}
                        {finding.exploitation_example && (
                          <Alert severity="warning" sx={{ mt: 2 }}>
                            <Typography variant="body2">
                              <strong>Exploitation:</strong> {finding.exploitation_example}
                            </Typography>
                          </Alert>
                        )}
                      </Paper>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )}

          {/* Documentation Analysis */}
          {selectedReport.documentation_analysis && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  📄 Documentation Analysis
                </Typography>
                <Divider sx={{ my: 2 }} />
                <ReactMarkdown components={markdownComponents}>{selectedReport.documentation_analysis}</ReactMarkdown>
              </CardContent>
            </Card>
          )}

          {/* Contextual Risk Scores */}
          {contextualRiskScores.length > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  📊 Contextual Risk Assessment
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Risk scores adjusted for real-world context: authentication requirements, network position, compensating controls, and threat intelligence
                </Typography>
                <Divider sx={{ my: 2 }} />

                {/* Priority Summary */}
                <Box sx={{ mb: 3, display: "flex", gap: 2, flexWrap: "wrap" }}>
                  {(() => {
                    const immediate = contextualRiskScores.filter(s => s.priority_level === "immediate").length;
                    const high = contextualRiskScores.filter(s => s.priority_level === "high").length;
                    const medium = contextualRiskScores.filter(s => s.priority_level === "medium").length;
                    return (
                      <>
                        {immediate > 0 && (
                          <Chip
                            label={`${immediate} Immediate (24-48h)`}
                            sx={{ bgcolor: alpha(theme.palette.error.main, 0.1), color: theme.palette.error.main, fontWeight: 600 }}
                          />
                        )}
                        {high > 0 && (
                          <Chip
                            label={`${high} High Priority (1-2 weeks)`}
                            sx={{ bgcolor: alpha(theme.palette.warning.main, 0.1), color: theme.palette.warning.main, fontWeight: 600 }}
                          />
                        )}
                        {medium > 0 && (
                          <Chip
                            label={`${medium} Medium Priority`}
                            sx={{ bgcolor: alpha(theme.palette.info.main, 0.1), color: theme.palette.info.main, fontWeight: 600 }}
                          />
                        )}
                      </>
                    );
                  })()}
                </Box>

                <Stack spacing={2}>
                  {contextualRiskScores.slice(0, 15).map((score, index) => (
                    <Accordion key={index} sx={{ border: `1px solid ${alpha(getRiskColor(score.contextual_severity || "unknown"), 0.3)}` }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <Chip
                            label={`${score.contextual_risk_score}/100`}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(score.contextual_severity || "unknown"), 0.1),
                              color: getRiskColor(score.contextual_severity || "unknown"),
                              fontWeight: 700,
                              minWidth: 60,
                            }}
                          />
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" fontWeight={600}>
                              {score.finding_title}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Original: {score.original_severity} → Contextual: {score.contextual_severity}
                              {score.priority_level === "immediate" && " 🔴 IMMEDIATE"}
                              {score.priority_level === "high" && " 🟠 HIGH"}
                            </Typography>
                          </Box>
                          <Chip label={score.recommended_timeline} size="small" variant="outlined" />
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={2}>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              Risk Drivers
                            </Typography>
                            <List dense>
                              {score.key_risk_drivers.map((driver, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 28 }}>
                                    <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: theme.palette.error.main }} />
                                  </ListItemIcon>
                                  <ListItemText primary={driver} primaryTypographyProps={{ variant: "body2" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              Risk Reducers
                            </Typography>
                            <List dense>
                              {score.risk_reducers.map((reducer, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 28 }}>
                                    <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: theme.palette.success.main }} />
                                  </ListItemIcon>
                                  <ListItemText primary={reducer} primaryTypographyProps={{ variant: "body2" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              Score Breakdown
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                              <Chip label={`Base: ${score.score_breakdown?.base_score || 0}`} size="small" variant="outlined" />
                              <Chip label={`Auth: ${(score.score_breakdown?.auth_modifier || 0) >= 0 ? "+" : ""}${score.score_breakdown?.auth_modifier || 0}`} size="small" variant="outlined" />
                              <Chip label={`Network: ${(score.score_breakdown?.network_modifier || 0) >= 0 ? "+" : ""}${score.score_breakdown?.network_modifier || 0}`} size="small" variant="outlined" />
                              <Chip label={`Complexity: ${(score.score_breakdown?.complexity_modifier || 0) >= 0 ? "+" : ""}${score.score_breakdown?.complexity_modifier || 0}`} size="small" variant="outlined" />
                              {(score.score_breakdown?.compensating_controls_modifier || 0) !== 0 && (
                                <Chip label={`Controls: ${score.score_breakdown?.compensating_controls_modifier || 0}`} size="small" variant="outlined" color="success" />
                              )}
                              {(score.score_breakdown?.threat_intel_modifier || 0) !== 0 && (
                                <Chip label={`Threat Intel: +${score.score_breakdown?.threat_intel_modifier || 0}`} size="small" variant="outlined" color="error" />
                              )}
                            </Box>
                          </Grid>
                          {score.additional_investigation_needed.length > 0 && (
                            <Grid item xs={12}>
                              <Alert severity="info" sx={{ mt: 1 }}>
                                <Typography variant="subtitle2" fontWeight={600}>
                                  Additional Investigation Needed:
                                </Typography>
                                <ul style={{ margin: "8px 0 0 0", paddingLeft: 20 }}>
                                  {score.additional_investigation_needed.map((item, i) => (
                                    <li key={i}><Typography variant="body2">{item}</Typography></li>
                                  ))}
                                </ul>
                              </Alert>
                            </Grid>
                          )}
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Evidence Collection Guides */}
          {evidenceGuides.length > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  🔍 Evidence Collection Guides
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Step-by-step guidance for capturing proof of exploitation and validating findings
                </Typography>
                <Divider sx={{ my: 2 }} />

                <Stack spacing={2}>
                  {evidenceGuides.map((guide, index) => (
                    <Accordion key={index} sx={{ border: `1px solid ${alpha(getRiskColor(guide.severity || "unknown"), 0.3)}` }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <Chip
                            label={guide.severity || "Unknown"}
                            size="small"
                            sx={{
                              bgcolor: alpha(getRiskColor(guide.severity || "unknown"), 0.1),
                              color: getRiskColor(guide.severity || "unknown"),
                              fontWeight: 600,
                            }}
                          />
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" fontWeight={600}>
                              {guide.finding_title}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              Type: {guide.finding_type} | Evidence folder: {guide.evidence_folder}
                            </Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={3}>
                          {/* Required Evidence */}
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              📸 Required Evidence
                            </Typography>
                            <Stack spacing={1}>
                              {guide.evidence_requirements.map((ev, i) => (
                                <Paper key={i} sx={{ p: 1.5, bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                                  <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1 }}>
                                    <Chip label={ev.priority} size="small" color={ev.priority === "Required" ? "error" : "default"} />
                                    <Box sx={{ flex: 1 }}>
                                      <Typography variant="body2" fontWeight={600}>{ev.description}</Typography>
                                      <Typography variant="caption" color="text.secondary" display="block">
                                        <strong>How:</strong> {ev.capture_method}
                                      </Typography>
                                      <Typography variant="caption" color="text.secondary" display="block">
                                        <strong>Expected:</strong> {ev.expected_content}
                                      </Typography>
                                      <Typography variant="caption" sx={{ fontFamily: "monospace", bgcolor: alpha(theme.palette.primary.main, 0.1), px: 0.5, borderRadius: 0.5 }}>
                                        Save as: {ev.filename}
                                      </Typography>
                                      {ev.tools.length > 0 && (
                                        <Box sx={{ mt: 0.5 }}>
                                          {ev.tools.map((tool, j) => (
                                            <Chip key={j} label={tool} size="small" variant="outlined" sx={{ mr: 0.5, height: 20, fontSize: "0.7rem" }} />
                                          ))}
                                        </Box>
                                      )}
                                    </Box>
                                  </Box>
                                </Paper>
                              ))}
                            </Stack>
                          </Grid>

                          {/* Validation Steps */}
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              ✅ Validation Steps
                            </Typography>
                            <List dense>
                              {guide.validation_steps.map((step: any, i: number) => (
                                <ListItem key={i} sx={{ py: 0.5, alignItems: "flex-start" }}>
                                  <ListItemIcon sx={{ minWidth: 28, mt: 0.5 }}>
                                    <Chip label={typeof step === 'object' ? step.step : i + 1} size="small" sx={{ width: 24, height: 24, fontSize: "0.75rem" }} />
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={typeof step === 'object' ? step.action : String(step)}
                                    secondary={
                                      typeof step === 'object' ? (
                                        <>
                                          <Typography variant="caption" color="success.main" display="block">
                                            ✓ Expected: {step.expected || 'N/A'}
                                          </Typography>
                                          <Typography variant="caption" color="warning.main" display="block">
                                            ✗ If fails: {step.if_fails || 'N/A'}
                                          </Typography>
                                        </>
                                      ) : null
                                    }
                                    primaryTypographyProps={{ variant: "body2", fontWeight: 500 }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>

                          {/* Quick Verify & Indicators */}
                          <Grid item xs={12} md={6}>
                            {guide.quick_verify && (
                              <Box sx={{ mb: 2 }}>
                                <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                                  ⚡ Quick Verification
                                </Typography>
                                <Box sx={{ p: 1.5, bgcolor: "#1e1e1e", borderRadius: 1, fontFamily: "monospace", fontSize: "0.8rem", color: "#22d3ee", overflow: "auto" }}>
                                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>{guide.quick_verify.command}</pre>
                                </Box>
                                <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                                  Expected: {guide.quick_verify.expected}
                                </Typography>
                              </Box>
                            )}

                            <Typography variant="subtitle2" fontWeight={600} color="success.main" gutterBottom>
                              ✓ True Positive Indicators
                            </Typography>
                            <List dense>
                              {guide.true_positive_indicators.slice(0, 3).map((ind, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemText primary={ind} primaryTypographyProps={{ variant: "caption" }} />
                                </ListItem>
                              ))}
                            </List>

                            <Typography variant="subtitle2" fontWeight={600} color="warning.main" gutterBottom sx={{ mt: 1 }}>
                              ✗ False Positive Indicators
                            </Typography>
                            <List dense>
                              {guide.false_positive_indicators.slice(0, 3).map((ind, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemText primary={ind} primaryTypographyProps={{ variant: "caption" }} />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Control Bypass Recommendations */}
          {controlBypassRecommendations.length > 0 && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  🛡️ Compensating Control Bypass Techniques
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Security controls were detected protecting vulnerable endpoints. Use these techniques to bypass them.
                </Typography>
                <Divider sx={{ my: 2 }} />

                <Stack spacing={2}>
                  {controlBypassRecommendations.map((guide: ControlBypassGuide, index: number) => (
                    <Accordion key={index} sx={{ border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}` }}>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <Chip
                            label={(guide.control_type || "unknown").replace("_", " ").toUpperCase()}
                            size="small"
                            sx={{
                              bgcolor: alpha(theme.palette.warning.main, 0.1),
                              color: theme.palette.warning.main,
                              fontWeight: 600,
                            }}
                          />
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" fontWeight={600}>
                              {guide.control_name}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {guide.bypass_techniques.length} bypass techniques available
                            </Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={3}>
                          {/* Description */}
                          <Grid item xs={12}>
                            <Typography variant="body2" color="text.secondary">
                              {guide.description}
                            </Typography>
                            {guide.prioritized_note && (
                              <Alert severity="info" sx={{ mt: 1 }}>
                                <strong>For this vulnerability:</strong> {guide.prioritized_note}
                              </Alert>
                            )}
                          </Grid>

                          {/* Detection Methods */}
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              🔍 How to Detect This Control
                            </Typography>
                            <List dense>
                              {guide.detection_methods.slice(0, 4).map((method, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemText
                                    primary={method}
                                    primaryTypographyProps={{ variant: "caption" }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>

                          {/* Common Misconfigurations */}
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom color="warning.main">
                              ⚠️ Common Misconfigurations
                            </Typography>
                            <List dense>
                              {guide.common_misconfigurations.slice(0, 4).map((misconfig, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemText
                                    primary={misconfig}
                                    primaryTypographyProps={{ variant: "caption" }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>

                          {/* Bypass Techniques */}
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              🔓 Bypass Techniques
                            </Typography>
                            <Stack spacing={1.5}>
                              {guide.bypass_techniques.slice(0, 5).map((technique, i) => (
                                <Paper
                                  key={i}
                                  sx={{
                                    p: 2,
                                    bgcolor: alpha(theme.palette.background.default, 0.5),
                                    border: `1px solid ${alpha(theme.palette.divider, 0.5)}`
                                  }}
                                >
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                                    <Typography variant="subtitle2" fontWeight={600}>
                                      {technique.name}
                                    </Typography>
                                    <Chip
                                      label={`Complexity: ${technique.complexity}`}
                                      size="small"
                                      variant="outlined"
                                      color={technique.complexity === "trivial" ? "success" : technique.complexity === "low" ? "info" : "warning"}
                                      sx={{ height: 20, fontSize: "0.7rem" }}
                                    />
                                    <Chip
                                      label={`Reliability: ${technique.reliability}`}
                                      size="small"
                                      variant="outlined"
                                      color={technique.reliability === "high" ? "success" : technique.reliability === "medium" ? "info" : "warning"}
                                      sx={{ height: 20, fontSize: "0.7rem" }}
                                    />
                                  </Box>
                                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                                    {technique.description}
                                  </Typography>

                                  {/* Steps */}
                                  {technique.steps.length > 0 && (
                                    <Box sx={{ mb: 1 }}>
                                      <Typography variant="caption" fontWeight={600} display="block" gutterBottom>
                                        Steps:
                                      </Typography>
                                      <ol style={{ margin: 0, paddingLeft: 20 }}>
                                        {technique.steps.slice(0, 3).map((step, j) => (
                                          <li key={j}>
                                            <Typography variant="caption">{step}</Typography>
                                          </li>
                                        ))}
                                      </ol>
                                    </Box>
                                  )}

                                  {/* Example Payloads */}
                                  {technique.example_payloads.length > 0 && (
                                    <Box sx={{ mb: 1 }}>
                                      <Typography variant="caption" fontWeight={600} display="block" gutterBottom>
                                        Example Payloads:
                                      </Typography>
                                      <Box sx={{
                                        p: 1,
                                        bgcolor: "#1e1e1e",
                                        borderRadius: 1,
                                        fontFamily: "monospace",
                                        fontSize: "0.75rem",
                                        color: "#22d3ee",
                                        overflow: "auto",
                                        maxHeight: 100
                                      }}>
                                        {technique.example_payloads.slice(0, 3).map((payload, j) => (
                                          <div key={j}>{payload}</div>
                                        ))}
                                      </Box>
                                    </Box>
                                  )}

                                  {/* Tools */}
                                  {technique.tools.length > 0 && (
                                    <Box>
                                      <Typography variant="caption" fontWeight={600}>Tools: </Typography>
                                      {technique.tools.map((tool, j) => (
                                        <Chip
                                          key={j}
                                          label={tool}
                                          size="small"
                                          variant="outlined"
                                          sx={{ mr: 0.5, height: 20, fontSize: "0.65rem" }}
                                        />
                                      ))}
                                    </Box>
                                  )}
                                </Paper>
                              ))}
                            </Stack>
                          </Grid>

                          {/* General Tips */}
                          <Grid item xs={12}>
                            <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                              💡 General Tips
                            </Typography>
                            <List dense>
                              {guide.general_tips.slice(0, 4).map((tip, i) => (
                                <ListItem key={i} sx={{ py: 0 }}>
                                  <ListItemIcon sx={{ minWidth: 24 }}>
                                    <Typography variant="caption" color="primary">•</Typography>
                                  </ListItemIcon>
                                  <ListItemText
                                    primary={tip}
                                    primaryTypographyProps={{ variant: "caption" }}
                                  />
                                </ListItem>
                              ))}
                            </List>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Document-Finding Correlation Summary */}
          {documentFindingCorrelation && !documentFindingCorrelation.error && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  📚 Document-Finding Correlation
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Analysis of how uploaded documentation relates to discovered vulnerabilities.
                </Typography>
                <Divider sx={{ my: 2 }} />

                {/* Coverage Stats */}
                <Grid container spacing={2} sx={{ mb: 3 }}>
                  <Grid item xs={6} md={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="success.main">
                        {documentFindingCorrelation.documentation_coverage_percent}%
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Documentation Coverage
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.info.main, 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="info.main">
                        {documentFindingCorrelation.findings_with_documentation}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Findings with Docs
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="warning.main">
                        {documentFindingCorrelation.findings_without_documentation}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Undocumented Findings
                      </Typography>
                    </Paper>
                  </Grid>
                  <Grid item xs={6} md={3}>
                    <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                      <Typography variant="h4" fontWeight={700} color="primary.main">
                        {documentFindingCorrelation.total_documents}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        Documents Analyzed
                      </Typography>
                    </Paper>
                  </Grid>
                </Grid>

                {/* Documents Referenced */}
                {Object.keys(documentFindingCorrelation.documents_referenced || {}).length > 0 && (
                  <Box sx={{ mb: 3 }}>
                    <Typography variant="subtitle2" fontWeight={600} gutterBottom>
                      📄 Documents Referenced by Findings
                    </Typography>
                    <Stack spacing={1}>
                      {Object.entries(documentFindingCorrelation.documents_referenced || {}).map(([docName, info]: [string, { finding_count: number; matched_terms: string[] }]) => (
                        <Paper
                          key={docName}
                          sx={{
                            p: 1.5,
                            display: "flex",
                            alignItems: "center",
                            justifyContent: "space-between",
                            bgcolor: alpha(theme.palette.background.default, 0.5),
                            border: `1px solid ${alpha(theme.palette.divider, 0.5)}`
                          }}
                        >
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <DescriptionIcon fontSize="small" color="primary" />
                            <Typography variant="body2" fontWeight={500}>
                              {docName}
                            </Typography>
                          </Box>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                            <Chip
                              label={`${info.finding_count} findings`}
                              size="small"
                              color="primary"
                              variant="outlined"
                            />
                            <Tooltip title={info.matched_terms.join(", ")}>
                              <Chip
                                label={`${info.matched_terms.length} terms`}
                                size="small"
                                variant="outlined"
                              />
                            </Tooltip>
                          </Box>
                        </Paper>
                      ))}
                    </Stack>
                  </Box>
                )}

                {/* Undocumented Endpoints */}
                {documentFindingCorrelation.undocumented_endpoints && documentFindingCorrelation.undocumented_endpoints.length > 0 && (
                  <Box>
                    <Typography variant="subtitle2" fontWeight={600} gutterBottom color="warning.main">
                      ⚠️ Endpoints Missing Documentation
                    </Typography>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
                      These vulnerable endpoints have no corresponding documentation. Consider documenting them.
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                      {documentFindingCorrelation.undocumented_endpoints.slice(0, 15).map((endpoint, i) => (
                        <Chip
                          key={i}
                          label={endpoint}
                          size="small"
                          sx={{
                            bgcolor: alpha(theme.palette.warning.main, 0.1),
                            color: theme.palette.warning.main,
                            fontFamily: "monospace",
                            fontSize: "0.7rem"
                          }}
                        />
                      ))}
                      {documentFindingCorrelation.undocumented_endpoints.length > 15 && (
                        <Chip
                          label={`+${documentFindingCorrelation.undocumented_endpoints.length - 15} more`}
                          size="small"
                          variant="outlined"
                        />
                      )}
                    </Box>
                  </Box>
                )}
              </CardContent>
            </Card>
          )}

          {/* Corroborated Findings with Document References */}
          {corroboratedFindings.length > 0 && corroboratedFindings.some((f: CorroboratedFinding) => f.has_documentation) && (
            <Card sx={{ mb: 3 }}>
              <CardContent>
                <Typography variant="h5" fontWeight={600} gutterBottom>
                  🔗 High-Confidence Findings with Documentation
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Findings corroborated by multiple scan sources with relevant documentation references.
                </Typography>
                <Divider sx={{ my: 2 }} />

                <Stack spacing={2}>
                  {corroboratedFindings
                    .filter((f: CorroboratedFinding) => f.has_documentation && f.document_correlations && f.document_correlations.length > 0)
                    .slice(0, 10)
                    .map((finding: CorroboratedFinding, index: number) => (
                    <Accordion
                      key={index}
                      sx={{
                        border: `1px solid ${alpha(
                          finding.severity === "Critical" ? theme.palette.error.main :
                          finding.severity === "High" ? theme.palette.warning.main :
                          theme.palette.info.main, 0.3
                        )}`
                      }}
                    >
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
                          <Chip
                            label={finding.severity}
                            size="small"
                            sx={{
                              bgcolor: alpha(
                                finding.severity === "Critical" ? theme.palette.error.main :
                                finding.severity === "High" ? theme.palette.warning.main :
                                finding.severity === "Medium" ? theme.palette.info.main :
                                theme.palette.success.main, 0.1
                              ),
                              color: finding.severity === "Critical" ? theme.palette.error.main :
                                     finding.severity === "High" ? theme.palette.warning.main :
                                     finding.severity === "Medium" ? theme.palette.info.main :
                                     theme.palette.success.main,
                              fontWeight: 600,
                            }}
                          />
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" fontWeight={600}>
                              {finding.finding_key}
                            </Typography>
                            <Typography variant="caption" color="text.secondary">
                              {finding.source_count} sources • {finding.confidence_level} confidence •{" "}
                              {finding.document_correlations?.length || 0} doc refs
                            </Typography>
                          </Box>
                        </Box>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Grid container spacing={2}>
                          {/* Sources */}
                          <Grid item xs={12} md={4}>
                            <Typography variant="caption" fontWeight={600} display="block" gutterBottom>
                              Detected By:
                            </Typography>
                            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                              {(finding.sources as string[] || []).map((source: string, i: number) => (
                                <Chip key={i} label={source} size="small" variant="outlined" />
                              ))}
                            </Box>
                          </Grid>

                          {/* Document References */}
                          <Grid item xs={12} md={8}>
                            <Typography variant="caption" fontWeight={600} display="block" gutterBottom>
                              📚 Related Documentation:
                            </Typography>
                            <Stack spacing={1}>
                              {finding.document_correlations?.slice(0, 3).map((corr: { document: string; matched_term: string; relevance_score: number; context?: string }, i: number) => (
                                <Paper
                                  key={i}
                                  sx={{
                                    p: 1.5,
                                    bgcolor: alpha(theme.palette.info.main, 0.05),
                                    border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`
                                  }}
                                >
                                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
                                    <DescriptionIcon fontSize="small" color="info" />
                                    <Typography variant="caption" fontWeight={600}>
                                      {corr.document}
                                    </Typography>
                                    <Chip
                                      label={`Matched: ${corr.matched_term}`}
                                      size="small"
                                      sx={{ height: 18, fontSize: "0.65rem" }}
                                    />
                                    <Chip
                                      label={`${Math.round(corr.relevance_score * 100)}% relevant`}
                                      size="small"
                                      color="info"
                                      variant="outlined"
                                      sx={{ height: 18, fontSize: "0.65rem" }}
                                    />
                                  </Box>
                                  <Typography
                                    variant="caption"
                                    color="text.secondary"
                                    sx={{
                                      display: "block",
                                      fontFamily: "monospace",
                                      fontSize: "0.7rem",
                                      bgcolor: alpha(theme.palette.background.default, 0.5),
                                      p: 1,
                                      borderRadius: 1,
                                      maxHeight: 80,
                                      overflow: "auto"
                                    }}
                                  >
                                    {(corr.context || "").slice(0, 300)}
                                    {(corr.context || "").length > 300 && "..."}
                                  </Typography>
                                </Paper>
                              ))}
                            </Stack>
                          </Grid>
                        </Grid>
                      </AccordionDetails>
                    </Accordion>
                  ))}
                </Stack>
              </CardContent>
            </Card>
          )}

          {/* Spacer for chat panel */}
          <Box sx={{ height: 80 }} />
        </Box>
      )}

      {/* AI Chat Panel - Fixed at bottom when viewing a report */}
      {selectedReport && activeTab === 2 && (
        <Paper
          elevation={6}
          sx={{
            position: "fixed",
            bottom: 16,
            right: 16,
            left: chatMaximized ? { xs: 16, md: 256 } : "auto",
            width: chatMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 400 },
            maxWidth: chatMaximized ? "none" : 400,
            zIndex: 1200,
            borderRadius: 3,
            overflow: "hidden",
            boxShadow: "0 4px 30px rgba(0,0,0,0.3)",
            transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => !chatMaximized && setChatOpen(!chatOpen)}
            sx={{
              p: 1.5,
              background: "linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)",
              color: "white",
              cursor: chatMaximized ? "default" : "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { filter: chatMaximized ? "none" : "brightness(1.1)" },
            }}
          >
            <Box 
              onClick={() => chatMaximized && setChatOpen(!chatOpen)}
              sx={{ 
                display: "flex", 
                alignItems: "center", 
                gap: 1, 
                cursor: "pointer",
                flex: 1,
              }}
            >
              <SmartToyIcon fontSize="small" />
              <Typography variant="body2" fontWeight={600}>
                AI Chat
              </Typography>
              {chatMessages.length > 0 && (
                <Chip
                  label={chatMessages.length}
                  size="small"
                  sx={{ 
                    bgcolor: "rgba(255,255,255,0.2)", 
                    color: "white",
                    height: 20,
                    "& .MuiChip-label": { px: 1, fontSize: "0.7rem" },
                  }}
                />
              )}
            </Box>
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <IconButton 
                size="small" 
                sx={{ color: "white", p: 0.5 }}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!chatOpen) setChatOpen(true);
                  setChatMaximized(!chatMaximized);
                }}
              >
                {chatMaximized ? <CloseFullscreenIcon fontSize="small" /> : <OpenInFullIcon fontSize="small" />}
              </IconButton>
              <IconButton 
                size="small" 
                sx={{ color: "white", p: 0.5 }}
                onClick={(e) => {
                  e.stopPropagation();
                  setChatOpen(!chatOpen);
                }}
              >
                {chatOpen ? <ExpandMoreIcon fontSize="small" /> : <ExpandLessIcon fontSize="small" />}
              </IconButton>
            </Box>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: chatMaximized ? "calc(66vh - 120px)" : 280,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.98),
                transition: "height 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: chatMaximized ? 6 : 2 }}>
                  <SmartToyIcon sx={{ fontSize: 48, color: "primary.main", mb: 1 }} />
                  <Typography variant="body1" fontWeight={600} gutterBottom>
                    I have full access to this report
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Ask me anything about the findings, vulnerabilities, PoC scripts, or remediation steps!
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, justifyContent: "center" }}>
                    {chatSuggestions.map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => sendChatMessage(suggestion)}
                        sx={{
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                        }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat messages */}
              {chatMessages.map((msg, index) => (
                <Box
                  key={index}
                  sx={{
                    display: "flex",
                    gap: 1.5,
                    mb: 2,
                    flexDirection: msg.role === "user" ? "row-reverse" : "row",
                  }}
                >
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      bgcolor: msg.role === "user" ? "primary.main" : "secondary.main",
                      color: "white",
                      flexShrink: 0,
                    }}
                  >
                    {msg.role === "user" ? <PersonIcon fontSize="small" /> : <SmartToyIcon fontSize="small" />}
                  </Box>
                  <Paper
                    sx={{
                      p: 1.5,
                      maxWidth: "75%",
                      bgcolor: msg.role === "user" 
                        ? alpha(theme.palette.primary.main, 0.1)
                        : alpha(theme.palette.background.paper, 0.9),
                      borderRadius: 2,
                      borderTopRightRadius: msg.role === "user" ? 0 : 2,
                      borderTopLeftRadius: msg.role === "user" ? 2 : 0,
                    }}
                  >
                    <ReactMarkdown components={markdownComponents}>{msg.content}</ReactMarkdown>
                  </Paper>
                </Box>
              ))}

              {/* Loading indicator */}
              {chatLoading && (
                <Box sx={{ display: "flex", gap: 1.5, mb: 2 }}>
                  <Box
                    sx={{
                      width: 32,
                      height: 32,
                      borderRadius: "50%",
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      bgcolor: "secondary.main",
                      color: "white",
                    }}
                  >
                    <SmartToyIcon fontSize="small" />
                  </Box>
                  <Paper sx={{ p: 1.5, bgcolor: alpha(theme.palette.background.paper, 0.9), borderRadius: 2 }}>
                    <Box sx={{ display: "flex", gap: 0.5 }}>
                      <CircularProgress size={8} />
                      <CircularProgress size={8} sx={{ animationDelay: "0.2s" }} />
                      <CircularProgress size={8} sx={{ animationDelay: "0.4s" }} />
                    </Box>
                  </Paper>
                </Box>
              )}

              {/* Follow-up suggestions */}
              {chatMessages.length > 0 && chatSuggestions.length > 0 && !chatLoading && (
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
                  {chatSuggestions.map((suggestion, i) => (
                    <Chip
                      key={i}
                      label={suggestion}
                      variant="outlined"
                      size="small"
                      onClick={() => sendChatMessage(suggestion)}
                      sx={{
                        cursor: "pointer",
                        fontSize: "0.75rem",
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                      }}
                    />
                  ))}
                </Box>
              )}

              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 1.5,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
                display: "flex",
                gap: 1,
              }}
            >
              <TextField
                fullWidth
                size="small"
                placeholder={chatMaximized ? "Ask about vulnerabilities, exploits, remediation..." : "Ask AI..."}
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyPress={handleChatKeyPress}
                disabled={chatLoading}
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 2,
                  },
                }}
              />
              <Button
                variant="contained"
                onClick={() => sendChatMessage()}
                disabled={!chatInput.trim() || chatLoading}
                sx={{
                  minWidth: 40,
                  borderRadius: 2,
                  background: "linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)",
                }}
              >
                <SendIcon fontSize="small" />
              </Button>
            </Box>
          </Collapse>
        </Paper>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Report?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to delete this report? This action cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={() => reportToDelete && deleteMutation.mutate(reportToDelete)}
            color="error"
            variant="contained"
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? "Deleting..." : "Delete"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
