import { useEffect, useMemo, useState, useRef, useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Treemap, ResponsiveContainer, Tooltip as RechartsTooltip, Sankey, Layer, Rectangle } from "recharts";
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
import "prismjs/components/prism-ruby";
import "prismjs/components/prism-php";
import "prismjs/components/prism-swift";
import "prismjs/components/prism-kotlin";
import "prismjs/components/prism-sql";
import "prismjs/components/prism-bash";
import "prismjs/components/prism-yaml";
import "prismjs/components/prism-json";
import "prismjs/components/prism-markdown";
import "prismjs/components/prism-css";
import "prismjs/components/prism-scss";
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Dialog,
  DialogContent,
  DialogTitle,
  Grid,
  IconButton,
  InputAdornment,
  LinearProgress,
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
  TableSortLabel,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  Theme,
  keyframes,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  Snackbar,
} from "@mui/material";
import { useNavigate, useParams } from "react-router-dom";
import { api, AIInsights, AttackChain, AttackChainDiagram, ChatMessage, CodebaseFile, CodebaseFolder, CodebaseNode, CodebaseSummary, CodebaseDiagram, ExploitScenario, Finding, FileContent, DependencyGraph, ScanDiff, FileTrends, TodoScanResult, TodoItem, CodeSearchResult, CodeSearchMatch, CodeExplanation, SecretsScanResult, SecretItem, VulnerabilitySummary, CVEEntry, CWEEntry } from "../api/client";
import { FindingNotesBadge } from "../components/FindingNotesPanel";
import { MermaidDiagram } from "../components/MermaidDiagram";

// AI Icon for explanation feature
const AIIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19,9L20.25,6.25L23,5L20.25,3.75L19,1L17.75,3.75L15,5L17.75,6.25L19,9Z M11.5,9.5L9,4L6.5,9.5L1,12L6.5,14.5L9,20L11.5,14.5L17,12L11.5,9.5Z M19,15L17.75,17.75L15,19L17.75,20.25L19,23L20.25,20.25L23,19L20.25,17.75L19,15Z" />
  </svg>
);
import ReactMarkdown from "react-markdown";
import { LineChart, Line, ResponsiveContainer as SparklineContainer } from "recharts";

// Animations
const fadeIn = keyframes`
  from { opacity: 0; transform: translateY(10px); }
  to { opacity: 1; transform: translateY(0); }
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
      transition: "transform 0.3s ease" 
    }}
  >
    <path d="M16.59 8.59L12 13.17 7.41 8.59 6 10l6 6 6-6z" />
  </svg>
);

const DownloadIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z" />
  </svg>
);

const SecurityIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z" />
  </svg>
);

const BugIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 8h-2.81c-.45-.78-1.07-1.45-1.82-1.96L17 4.41 15.59 3l-2.17 2.17C12.96 5.06 12.49 5 12 5c-.49 0-.96.06-1.41.17L8.41 3 7 4.41l1.62 1.63C7.88 6.55 7.26 7.22 6.81 8H4v2h2.09c-.05.33-.09.66-.09 1v1H4v2h2v1c0 .34.04.67.09 1H4v2h2.81c1.04 1.79 2.97 3 5.19 3s4.15-1.21 5.19-3H20v-2h-2.09c.05-.33.09-.66.09-1v-1h2v-2h-2v-1c0-.34-.04-.67-.09-1H20V8zm-6 8h-4v-2h4v2zm0-4h-4v-2h4v2z" />
  </svg>
);

const AnalysisIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19.88 18.47c.44-.7.7-1.51.7-2.39 0-2.49-2.01-4.5-4.5-4.5s-4.5 2.01-4.5 4.5 2.01 4.5 4.5 4.5c.88 0 1.69-.26 2.39-.7L21.59 23 23 21.59l-3.12-3.12zm-4.8.21c-1.38 0-2.5-1.12-2.5-2.5s1.12-2.5 2.5-2.5 2.5 1.12 2.5 2.5-1.12 2.5-2.5 2.5zM12 20v2C6.48 22 2 17.52 2 12S6.48 2 12 2c4.84 0 8.87 3.44 9.8 8h-2.07c-.64-3.13-3.38-5.5-6.73-5.5-3.87 0-7 3.13-7 7s3.13 7 7 7v-2h-2v-2h2v-2h2v2h2v2h-2v2z" />
  </svg>
);

const CodeIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9.4 16.6L4.8 12l4.6-4.6L8 6l-6 6 6 6 1.4-1.4zm5.2 0l4.6-4.6-4.6-4.6L16 6l6 6-6 6-1.4-1.4z" />
  </svg>
);

const FolderIcon = ({ open }: { open?: boolean }) => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    {open ? (
      <path d="M20 6h-8l-2-2H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm0 12H4V8h16v10z" />
    ) : (
      <path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z" />
    )}
  </svg>
);

const FileIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z" />
  </svg>
);

const ChevronIcon = ({ expanded }: { expanded: boolean }) => (
  <svg 
    width="18" 
    height="18" 
    viewBox="0 0 24 24" 
    fill="currentColor"
    style={{ 
      transform: expanded ? "rotate(90deg)" : "rotate(0deg)", 
      transition: "transform 0.2s ease" 
    }}
  >
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
  </svg>
);

const InfoIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
  </svg>
);

const MapIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20.5 3l-.16.03L15 5.1 9 3 3.36 4.9c-.21.07-.36.25-.36.48V20.5c0 .28.22.5.5.5l.16-.03L9 18.9l6 2.1 5.64-1.9c.21-.07.36-.25.36-.48V3.5c0-.28-.22-.5-.5-.5zM15 19l-6-2.11V5l6 2.11V19z" />
  </svg>
);

const CloseIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
  </svg>
);

const NavigateNextIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z" />
  </svg>
);

const HomeIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8z" />
  </svg>
);

const JumpIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 19H5V5h7V3H5c-1.11 0-2 .9-2 2v14c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2v-7h-2v7zM14 3v2h3.59l-9.83 9.83 1.41 1.41L19 6.41V10h2V3h-7z" />
  </svg>
);

// Copy icon for code preview
const CopyIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M16 1H4c-1.1 0-2 .9-2 2v14h2V3h12V1zm3 4H8c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h11c1.1 0 2-.9 2-2V7c0-1.1-.9-2-2-2zm0 16H8V7h11v14z" />
  </svg>
);

// Check icon for copy confirmation
const CheckIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
    <path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z" />
  </svg>
);

// Prism language mapping
const getPrismLanguage = (language: string): string => {
  const mapping: Record<string, string> = {
    python: "python",
    javascript: "javascript",
    javascriptreact: "javascript",
    typescript: "typescript",
    typescriptreact: "typescript",
    java: "java",
    c: "c",
    cpp: "cpp",
    csharp: "csharp",
    go: "go",
    rust: "rust",
    ruby: "ruby",
    php: "php",
    swift: "swift",
    kotlin: "kotlin",
    sql: "sql",
    shell: "bash",
    bash: "bash",
    yaml: "yaml",
    yml: "yaml",
    json: "json",
    jsonc: "json",
    markdown: "markdown",
    md: "markdown",
    css: "css",
    scss: "scss",
    html: "markup",
    xml: "markup",
  };
  return mapping[language?.toLowerCase()] || "clike";
};

// Syntax highlight code
const highlightCode = (code: string, language: string): string => {
  try {
    const prismLang = getPrismLanguage(language);
    if (Prism.languages[prismLang]) {
      return Prism.highlight(code, Prism.languages[prismLang], prismLang);
    }
  } catch (e) {
    // Fallback to plain text
  }
  return code.replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

const ChatIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M21 6h-2v9H6v2c0 .55.45 1 1 1h11l4 4V7c0-.55-.45-1-1-1zm-4 6V3c0-.55-.45-1-1-1H3c-.55 0-1 .45-1 1v14l4-4h10c.55 0 1-.45 1-1z" />
  </svg>
);

const SendIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
  </svg>
);

const SmartToyIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M20 9V7c0-1.1-.9-2-2-2h-3c0-1.66-1.34-3-3-3S9 3.34 9 5H6c-1.1 0-2 .9-2 2v2c-1.66 0-3 1.34-3 3s1.34 3 3 3v4c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2v-4c1.66 0 3-1.34 3-3s-1.34-3-3-3zM7.5 11.5c0-.83.67-1.5 1.5-1.5s1.5.67 1.5 1.5S9.83 13 9 13s-1.5-.67-1.5-1.5zM16 17H8v-2h8v2zm-1-4c-.83 0-1.5-.67-1.5-1.5S14.17 10 15 10s1.5.67 1.5 1.5S15.83 13 15 13z" />
  </svg>
);

const PersonIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z" />
  </svg>
);

const ExpandMoreIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M16.59 8.59L12 13.17 7.41 8.59 6 10l6 6 6-6z" />
  </svg>
);

const ExpandLessIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M12 8l-6 6 1.41 1.41L12 10.83l4.59 4.58L18 14z" />
  </svg>
);

const SearchIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
    <path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z" />
  </svg>
);

const ClearIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
    <path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" />
  </svg>
);

// Severity styling
const getSeverityConfig = (severity: string, theme: Theme) => {
  const configs: Record<string, { color: string; bg: string; label: string; order: number }> = {
    critical: { color: theme.palette.error.main, bg: alpha(theme.palette.error.main, 0.15), label: "CRITICAL", order: 0 },
    high: { color: "#f97316", bg: alpha("#f97316", 0.15), label: "HIGH", order: 1 },
    medium: { color: theme.palette.warning.main, bg: alpha(theme.palette.warning.main, 0.15), label: "MEDIUM", order: 2 },
    low: { color: theme.palette.info.main, bg: alpha(theme.palette.info.main, 0.15), label: "LOW", order: 3 },
    info: { color: theme.palette.grey[500], bg: alpha(theme.palette.grey[500], 0.15), label: "INFO", order: 4 },
  };
  return configs[severity?.toLowerCase()] || configs.info;
};

// Risk score display
const RiskScoreDisplay = ({ score, size = "large" }: { score: number | null | undefined; size?: "small" | "large" }) => {
  const theme = useTheme();
  const getColor = () => {
    if (score == null) return theme.palette.grey[500];
    if (score >= 80) return theme.palette.error.main;
    if (score >= 60) return "#f97316";
    if (score >= 40) return theme.palette.warning.main;
    return theme.palette.success.main;
  };

  const displaySize = size === "large" ? 100 : 60;
  const fontSize = size === "large" ? "h3" : "h6";

  return (
    <Box sx={{ position: "relative", display: "inline-flex" }}>
      <CircularProgress
        variant="determinate"
        value={100}
        size={displaySize}
        sx={{ color: alpha(getColor(), 0.2) }}
      />
      <CircularProgress
        variant="determinate"
        value={score ?? 0}
        size={displaySize}
        sx={{ color: getColor(), position: "absolute", left: 0 }}
      />
      <Box
        sx={{
          position: "absolute",
          top: 0,
          left: 0,
          bottom: 0,
          right: 0,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <Typography variant={fontSize} fontWeight={700} color={getColor()}>
          {score != null ? Math.round(score) : "—"}
        </Typography>
      </Box>
    </Box>
  );
};

// Code snippet component
interface CodeSnippetViewProps {
  reportId: number;
  finding: Finding;
}

function CodeSnippetView({ reportId, finding }: CodeSnippetViewProps) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);
  
  const snippetQuery = useQuery({
    queryKey: ["snippet", reportId, finding.id],
    queryFn: () => api.getCodeSnippet(reportId, finding.id),
    enabled: expanded,
    staleTime: Infinity,
  });

  // Check if we have a code snippet in details already
  const inlineSnippet = finding.details?.code_snippet as string | undefined;
  const maskedValue = finding.details?.masked_value as string | undefined;

  return (
    <Box>
      <Button
        size="small"
        startIcon={<CodeIcon />}
        endIcon={<ExpandIcon expanded={expanded} />}
        onClick={() => setExpanded(!expanded)}
        sx={{
          textTransform: "none",
          color: "text.secondary",
          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
        }}
      >
        {expanded ? "Hide Code" : "View Code"}
      </Button>
      
      <Collapse in={expanded}>
        <Box sx={{ mt: 2 }}>
          {snippetQuery.isLoading && !inlineSnippet && !maskedValue && (
            <Box sx={{ p: 2 }}>
              <Skeleton variant="rectangular" height={100} />
            </Box>
          )}
          
          {(inlineSnippet || snippetQuery.data?.code_snippet || maskedValue) && (
            <Paper
              sx={{
                p: 0,
                overflow: "hidden",
                bgcolor: "#1e1e1e",
                borderRadius: 2,
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              }}
            >
              <Box
                sx={{
                  px: 2,
                  py: 1,
                  bgcolor: alpha(theme.palette.background.paper, 0.1),
                  borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                }}
              >
                <Typography variant="caption" sx={{ color: "#888", fontFamily: "monospace" }}>
                  {finding.file_path}
                  {finding.start_line && `:${finding.start_line}`}
                  {finding.end_line && finding.end_line !== finding.start_line && `-${finding.end_line}`}
                </Typography>
                <Chip
                  size="small"
                  label={snippetQuery.data?.language || finding.type}
                  sx={{ 
                    bgcolor: alpha(theme.palette.primary.main, 0.2),
                    color: theme.palette.primary.light,
                    fontSize: "0.65rem",
                    height: 20,
                  }}
                />
              </Box>
              <Box
                component="pre"
                sx={{
                  m: 0,
                  p: 2,
                  overflow: "auto",
                  maxHeight: 300,
                  fontSize: "0.8rem",
                  lineHeight: 1.6,
                  fontFamily: "'Fira Code', 'Consolas', monospace",
                  color: "#d4d4d4",
                  "& .line-number": {
                    color: "#6e7681",
                    userSelect: "none",
                    pr: 2,
                    borderRight: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                    mr: 2,
                  },
                }}
              >
                <code>
                  {(inlineSnippet || snippetQuery.data?.code_snippet || maskedValue || "").split("\n").map((line, i) => (
                    <Box key={i} component="span" sx={{ display: "block" }}>
                      <span className="line-number">
                        {String((finding.start_line || 1) + i).padStart(4, " ")}
                      </span>
                      {line || " "}
                    </Box>
                  ))}
                </code>
              </Box>
            </Paper>
          )}
          
          {!inlineSnippet && !maskedValue && snippetQuery.data?.source === "none" && finding.details && (
            <Paper
              sx={{
                p: 2,
                bgcolor: alpha(theme.palette.info.main, 0.05),
                border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
                borderRadius: 2,
              }}
            >
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
                Finding Details:
              </Typography>
              <Box component="pre" sx={{ m: 0, fontSize: "0.75rem", fontFamily: "monospace", overflow: "auto" }}>
                {JSON.stringify(finding.details, null, 2)}
              </Box>
            </Paper>
          )}
        </Box>
      </Collapse>
    </Box>
  );
}

// Language color mapping (comprehensive)
const getLanguageColor = (language: string | undefined, theme: Theme) => {
  const colors: Record<string, string> = {
    // Programming languages
    python: "#3572A5",
    javascript: "#f1e05a",
    javascriptreact: "#f1e05a",
    typescript: "#3178c6",
    typescriptreact: "#3178c6",
    java: "#b07219",
    go: "#00ADD8",
    rust: "#dea584",
    ruby: "#701516",
    php: "#4F5D95",
    c: "#555555",
    cpp: "#f34b7d",
    csharp: "#178600",
    swift: "#ffac45",
    kotlin: "#A97BFF",
    scala: "#c22d40",
    groovy: "#4298b8",
    perl: "#0298c3",
    lua: "#000080",
    r: "#198CE7",
    elixir: "#6e4a7e",
    erlang: "#B83998",
    haskell: "#5e5086",
    clojure: "#db5855",
    "objective-c": "#438eff",
    
    // Web/Markup
    html: "#e34c26",
    css: "#563d7c",
    scss: "#c6538c",
    sass: "#a53b70",
    less: "#1d365d",
    vue: "#41b883",
    svelte: "#ff3e00",
    
    // Data/Config
    json: "#292929",
    jsonc: "#292929",
    yaml: "#cb171e",
    xml: "#0060ac",
    toml: "#9c4221",
    ini: "#d1dbe0",
    
    // Documentation
    markdown: "#083fa1",
    restructuredtext: "#141414",
    plaintext: "#888888",
    
    // Database
    sql: "#e38c00",
    
    // Shell/Scripts
    shell: "#89e051",
    powershell: "#012456",
    batch: "#C1F12E",
    
    // DevOps/Build
    dockerfile: "#384d54",
    terraform: "#7B42BC",
    bicep: "#0078D4",
    makefile: "#427819",
    cmake: "#064F8C",
    
    // GraphQL/API
    graphql: "#e10098",
    protobuf: "#4285F4",
    
    // Images (for display reference)
    image: "#888888",
    svg: "#FFB13B",
    
    // Special
    env: "#ECD53F",
    gitignore: "#F05032",
    lockfile: "#6c757d",
    unknown: "#808080",
  };
  const lang = language?.toLowerCase() || "";
  return colors[lang] || theme.palette.grey[500];
};

// Detect language from file extension (fallback for old scans)
const detectLanguageFromPath = (filePath: string): string => {
  const ext = filePath.split(".").pop()?.toLowerCase() || "";
  const filename = filePath.split("/").pop()?.toLowerCase() || "";
  
  // Special filenames first
  const specialFiles: Record<string, string> = {
    "dockerfile": "dockerfile",
    "makefile": "makefile",
    "gemfile": "ruby",
    "rakefile": "ruby",
    "podfile": "ruby",
    "vagrantfile": "ruby",
    "jenkinsfile": "groovy",
    "cmakelists.txt": "cmake",
    ".gitignore": "gitignore",
    ".dockerignore": "dockerfile",
    ".env": "env",
    ".env.local": "env",
    ".env.example": "env",
  };
  
  if (specialFiles[filename]) return specialFiles[filename];
  
  // Extension mapping
  const extMap: Record<string, string> = {
    // Web
    "php": "php", "phtml": "php", "php3": "php", "php4": "php", "php5": "php",
    "js": "javascript", "mjs": "javascript", "cjs": "javascript", "jsx": "javascript",
    "ts": "typescript", "tsx": "typescript", "mts": "typescript", "cts": "typescript",
    "html": "html", "htm": "html", "xhtml": "html",
    "css": "css", "scss": "scss", "sass": "sass", "less": "less",
    "vue": "vue", "svelte": "svelte",
    
    // Backend
    "py": "python", "pyw": "python", "pyx": "python",
    "java": "java", "kt": "kotlin", "kts": "kotlin",
    "go": "go", "rs": "rust", "rb": "ruby", "erb": "ruby",
    "cs": "csharp", "fs": "fsharp", "vb": "vb",
    "swift": "swift", "m": "objective-c", "mm": "objective-c",
    "c": "c", "h": "c", "cpp": "cpp", "cc": "cpp", "cxx": "cpp", "hpp": "cpp",
    "scala": "scala", "clj": "clojure", "ex": "elixir", "exs": "elixir",
    "lua": "lua", "pl": "perl", "pm": "perl", "r": "r",
    "dart": "dart", "zig": "zig", "nim": "nim", "v": "v",
    
    // Config/Data
    "json": "json", "yaml": "yaml", "yml": "yaml", "toml": "toml",
    "xml": "xml", "csv": "csv", "ini": "ini", "conf": "config",
    "md": "markdown", "rst": "restructuredtext", "txt": "text",
    
    // Shell/Scripts
    "sh": "shell", "bash": "shell", "zsh": "shell", "fish": "shell",
    "ps1": "powershell", "psm1": "powershell", "bat": "batch", "cmd": "batch",
    
    // DevOps/IaC
    "tf": "terraform", "hcl": "terraform",
    "sql": "sql", "graphql": "graphql", "gql": "graphql",
    "proto": "protobuf",
    
    // Other
    "asm": "assembly", "s": "assembly",
    "lock": "lockfile",
  };
  
  return extMap[ext] || "unknown";
};

// Get effective language (use detected if stored is unknown)
const getEffectiveLanguage = (file: { path: string; language?: string }): string => {
  if (file.language && file.language.toLowerCase() !== "unknown") {
    return file.language;
  }
  return detectLanguageFromPath(file.path);
};

// File metadata dialog
interface FileMetadataDialogProps {
  file: CodebaseFile | null;
  open: boolean;
  onClose: () => void;
}

function FileMetadataDialog({ file, open, onClose }: FileMetadataDialogProps) {
  const theme = useTheme();
  
  if (!file) return null;

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.paper, 0.9)} 100%)`,
          backdropFilter: "blur(20px)",
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
        }
      }}
    >
      <DialogTitle sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <Stack direction="row" alignItems="center" spacing={1}>
          <FileIcon />
          <Typography variant="h6" fontWeight={600}>File Metadata</Typography>
        </Stack>
        <IconButton onClick={onClose} size="small">
          <CloseIcon />
        </IconButton>
      </DialogTitle>
      <DialogContent>
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.default, 0.5),
            borderRadius: 2,
            mb: 2,
          }}
        >
          <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-all" }}>
            {file.path}
          </Typography>
        </Paper>
        
        <Grid container spacing={2}>
          <Grid item xs={6}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
              <Typography variant="h4" fontWeight={700} color="primary">
                {file.lines}
              </Typography>
              <Typography variant="caption" color="text.secondary">Lines</Typography>
            </Paper>
          </Grid>
          <Grid item xs={6}>
            <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.05) }}>
              <Typography variant="h4" fontWeight={700} color="secondary">
                {file.chunks}
              </Typography>
              <Typography variant="caption" color="text.secondary">Code Chunks</Typography>
            </Paper>
          </Grid>
        </Grid>

        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            Language
          </Typography>
          <Chip 
            label={getEffectiveLanguage(file)} 
            size="small"
            sx={{ 
              bgcolor: alpha(getLanguageColor(getEffectiveLanguage(file), theme), 0.15),
              color: getLanguageColor(getEffectiveLanguage(file), theme),
              fontWeight: 600,
            }}
          />
        </Box>

        {file.findings.total > 0 && (
          <Box sx={{ mt: 3 }}>
            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
              Findings in this file
            </Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {file.findings.critical > 0 && (
                <Chip 
                  label={`${file.findings.critical} Critical`} 
                  size="small" 
                  sx={{ bgcolor: alpha(theme.palette.error.main, 0.15), color: theme.palette.error.main, fontWeight: 600 }}
                />
              )}
              {file.findings.high > 0 && (
                <Chip 
                  label={`${file.findings.high} High`} 
                  size="small" 
                  sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }}
                />
              )}
              {file.findings.medium > 0 && (
                <Chip 
                  label={`${file.findings.medium} Medium`} 
                  size="small" 
                  sx={{ bgcolor: alpha(theme.palette.warning.main, 0.15), color: theme.palette.warning.main, fontWeight: 600 }}
                />
              )}
              {file.findings.low > 0 && (
                <Chip 
                  label={`${file.findings.low} Low`} 
                  size="small" 
                  sx={{ bgcolor: alpha(theme.palette.info.main, 0.15), color: theme.palette.info.main, fontWeight: 600 }}
                />
              )}
            </Stack>
          </Box>
        )}
      </DialogContent>
    </Dialog>
  );
}

// Folder/File tree node
interface TreeNodeProps {
  node: CodebaseNode;
  depth: number;
  expandedFolders: Set<string>;
  onToggleFolder: (path: string) => void;
  onShowMetadata: (file: CodebaseFile) => void;
  searchQuery?: string;
  onFileClick?: (file: CodebaseFile) => void;
  selectedPath?: string | null;
}

function TreeNode({ node, depth, expandedFolders, onToggleFolder, onShowMetadata, searchQuery = "", onFileClick, selectedPath }: TreeNodeProps) {
  const theme = useTheme();
  const isFolder = node.type === "folder";
  const isExpanded = isFolder && expandedFolders.has(node.path);
  const isSelected = !isFolder && selectedPath === node.path;
  
  // Highlight matching text
  const highlightMatch = (text: string) => {
    if (!searchQuery.trim()) return text;
    const query = searchQuery.toLowerCase();
    const index = text.toLowerCase().indexOf(query);
    if (index === -1) return text;
    return (
      <>
        {text.slice(0, index)}
        <Box component="span" sx={{ bgcolor: alpha(theme.palette.warning.main, 0.4), borderRadius: 0.5, px: 0.25 }}>
          {text.slice(index, index + query.length)}
        </Box>
        {text.slice(index + query.length)}
      </>
    );
  };
  
  const getFindingsBadge = (findings: { critical: number; high: number; medium: number; low: number; total: number }) => {
    if (findings.critical > 0) return { color: theme.palette.error.main, count: findings.critical };
    if (findings.high > 0) return { color: "#f97316", count: findings.high };
    if (findings.medium > 0) return { color: theme.palette.warning.main, count: findings.medium };
    if (findings.low > 0) return { color: theme.palette.info.main, count: findings.low };
    return null;
  };

  const badge = getFindingsBadge(node.findings);

  const handleClick = () => {
    if (isFolder) {
      onToggleFolder(node.path);
    } else if (onFileClick) {
      onFileClick(node as CodebaseFile);
    }
  };

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          py: 0.5,
          px: 1,
          pl: depth * 2 + 1,
          cursor: isFolder || onFileClick ? "pointer" : "default",
          borderRadius: 1,
          transition: "all 0.15s ease",
          bgcolor: isSelected ? alpha(theme.palette.primary.main, 0.1) : "transparent",
          borderLeft: isSelected ? `3px solid ${theme.palette.primary.main}` : "3px solid transparent",
          "&:hover": {
            bgcolor: alpha(theme.palette.primary.main, 0.05),
          },
        }}
        onClick={handleClick}
      >
        {isFolder && (
          <Box sx={{ mr: 0.5, display: "flex", alignItems: "center", color: "text.secondary" }}>
            <ChevronIcon expanded={isExpanded} />
          </Box>
        )}
        <Box 
          sx={{ 
            mr: 1, 
            display: "flex", 
            alignItems: "center",
            color: isFolder 
              ? (isExpanded ? theme.palette.warning.main : theme.palette.warning.dark)
              : getLanguageColor((node as CodebaseFile).language, theme),
          }}
        >
          {isFolder ? <FolderIcon open={isExpanded} /> : <FileIcon />}
        </Box>
        <Typography 
          variant="body2" 
          component="div"
          sx={{ 
            fontFamily: "monospace",
            fontSize: "0.95rem",
            flex: 1,
            fontWeight: isFolder ? 600 : 400,
          }}
        >
          {highlightMatch(node.name)}
        </Typography>
        
        {badge && (
          <Chip
            size="small"
            label={badge.count}
            sx={{
              height: 18,
              minWidth: 24,
              bgcolor: alpha(badge.color, 0.15),
              color: badge.color,
              fontWeight: 700,
              fontSize: "0.65rem",
              "& .MuiChip-label": { px: 0.75 },
            }}
          />
        )}
        
        {isFolder && (
          <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            {(node as CodebaseFolder).file_count} files
          </Typography>
        )}
        
        {!isFolder && (
          <Tooltip title="View metadata">
            <IconButton
              size="small"
              onClick={(e) => {
                e.stopPropagation();
                onShowMetadata(node as CodebaseFile);
              }}
              sx={{
                ml: 1,
                opacity: 0.6,
                "&:hover": { opacity: 1, bgcolor: alpha(theme.palette.primary.main, 0.1) },
              }}
            >
              <InfoIcon />
            </IconButton>
          </Tooltip>
        )}
      </Box>
      
      {isFolder && isExpanded && (
        <Collapse in={isExpanded}>
          <Box>
            {(node as CodebaseFolder).children.map((child) => (
              <TreeNode
                key={child.path}
                node={child}
                depth={depth + 1}
                expandedFolders={expandedFolders}
                onToggleFolder={onToggleFolder}
                onShowMetadata={onShowMetadata}
                searchQuery={searchQuery}
                onFileClick={onFileClick}
                selectedPath={selectedPath}
              />
            ))}
          </Box>
        </Collapse>
      )}
    </Box>
  );
}

// Codebase Map View component
interface CodebaseMapViewProps {
  reportId: number;
  projectId: number;
  availableReports?: { id: number; created_at: string }[];
}

// Severity filter type
type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

// View mode type - expanded with new views
type ViewMode = "tree" | "treemap" | "dependencies" | "diff" | "todos" | "secrets" | "diagram" | "cves";

function CodebaseMapView({ reportId, projectId, availableReports = [] }: CodebaseMapViewProps) {
  const theme = useTheme();
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [selectedFile, setSelectedFile] = useState<CodebaseFile | null>(null);
  const [metadataOpen, setMetadataOpen] = useState(false);
  
  // Quick win states
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [selectedLanguages, setSelectedLanguages] = useState<Set<string>>(new Set());
  const [showStats, setShowStats] = useState(true);
  
  // View mode state
  const [viewMode, setViewMode] = useState<ViewMode>("tree");
  
  // Code preview state
  const [previewFile, setPreviewFile] = useState<string | null>(null);
  const [showCodePreview, setShowCodePreview] = useState(true);
  
  // Search dropdown state (Feature 2)
  const [searchFocused, setSearchFocused] = useState(false);
  const searchRef = useRef<HTMLDivElement>(null);
  
  // Jump to finding ref (Feature 4)
  const codePreviewRef = useRef<HTMLDivElement>(null);
  const [highlightedFindingLine, setHighlightedFindingLine] = useState<number | null>(null);
  
  // Diff view state (Feature 5)
  const [compareReportId, setCompareReportId] = useState<number | null>(null);
  
  // Copy code state
  const [codeCopied, setCodeCopied] = useState(false);
  
  // Heatmap mode state
  const [heatmapMode, setHeatmapMode] = useState(false);
  
  // Content search state
  const [contentSearchQuery, setContentSearchQuery] = useState("");
  const [contentSearchResults, setContentSearchResults] = useState<CodeSearchResult | null>(null);
  const [isSearchingContent, setIsSearchingContent] = useState(false);
  const [searchMode, setSearchMode] = useState<"filename" | "content">("filename");
  
  // AI Explanation state
  const [showExplanation, setShowExplanation] = useState(false);
  const [explanation, setExplanation] = useState<CodeExplanation | null>(null);
  const [isExplaining, setIsExplaining] = useState(false);
  
  // Filter to only reports older than current one for comparison
  const comparableReports = useMemo(() => {
    return availableReports.filter(r => r.id !== reportId).sort((a, b) => 
      new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    );
  }, [availableReports, reportId]);

  const codebaseQuery = useQuery({
    queryKey: ["codebase", reportId],
    queryFn: () => api.getCodebaseStructure(reportId),
    enabled: !!reportId,
  });

  // Query for file content preview
  const fileContentQuery = useQuery({
    queryKey: ["fileContent", reportId, previewFile],
    queryFn: () => api.getFileContent(reportId, previewFile!),
    enabled: !!reportId && !!previewFile,
  });

  // Query for dependencies
  const dependenciesQuery = useQuery({
    queryKey: ["dependencies", reportId],
    queryFn: () => api.getDependencies(reportId),
    enabled: !!reportId && viewMode === "dependencies",
  });
  
  // Query for scan diff (Feature 5)
  const diffQuery = useQuery({
    queryKey: ["scanDiff", reportId, compareReportId],
    queryFn: () => api.getScanDiff(reportId, compareReportId!),
    enabled: !!reportId && !!compareReportId && viewMode === "diff",
  });
  
  // Query for TODOs (Feature: TODO/FIXME Scanner)
  const todosQuery = useQuery({
    queryKey: ["todos", reportId],
    queryFn: () => api.getTodos(reportId),
    enabled: !!reportId && viewMode === "todos",
  });
  
  // Query for Secrets (Feature: Secrets/Sensitive Data Scanner)
  const secretsQuery = useQuery({
    queryKey: ["secrets", reportId],
    queryFn: () => api.getSecrets(reportId),
    enabled: !!reportId && viewMode === "secrets",
  });
  
  // Query for AI-generated architecture diagram
  const diagramQuery = useQuery({
    queryKey: ["codebaseDiagram", reportId],
    queryFn: () => api.getCodebaseDiagram(reportId),
    enabled: !!reportId && viewMode === "diagram",
    staleTime: 1000 * 60 * 30, // Cache for 30 minutes (diagram generation is expensive)
  });
  
  // Query for CVE/CWE vulnerabilities
  const cvesQuery = useQuery({
    queryKey: ["vulnerabilities", reportId],
    queryFn: () => api.getVulnerabilities(reportId),
    enabled: !!reportId && viewMode === "cves",
  });
  
  // Query for file trends (Feature: Finding Trends Sparkline)
  const fileTrendsQuery = useQuery({
    queryKey: ["fileTrends", reportId, previewFile],
    queryFn: () => api.getFileTrends(reportId, previewFile!),
    enabled: !!reportId && !!previewFile,
  });

  // Collect all files for filtering
  const allFiles = useMemo(() => {
    if (!codebaseQuery.data) return [];
    const files: CodebaseFile[] = [];
    const collectFiles = (nodes: CodebaseNode[]) => {
      for (const node of nodes) {
        if (node.type === "folder") {
          collectFiles((node as CodebaseFolder).children);
        } else {
          files.push(node as CodebaseFile);
        }
      }
    };
    collectFiles(codebaseQuery.data.tree);
    return files;
  }, [codebaseQuery.data]);

  // Calculate language statistics
  const languageStats = useMemo(() => {
    const stats: Record<string, { files: number; lines: number; findings: number }> = {};
    for (const file of allFiles) {
      const lang = getEffectiveLanguage(file);
      if (!stats[lang]) {
        stats[lang] = { files: 0, lines: 0, findings: 0 };
      }
      stats[lang].files++;
      stats[lang].lines += file.lines || 0;
      stats[lang].findings += file.findings.total || 0;
    }
    return Object.entries(stats)
      .map(([lang, data]) => ({ language: lang, ...data }))
      .sort((a, b) => b.files - a.files);
  }, [allFiles]);

  // Fuzzy search filter
  const matchesSearch = useCallback((node: CodebaseNode): boolean => {
    if (!searchQuery.trim()) return true;
    const query = searchQuery.toLowerCase();
    // Match file/folder name or path
    if (node.name.toLowerCase().includes(query)) return true;
    if (node.path.toLowerCase().includes(query)) return true;
    return false;
  }, [searchQuery]);

  // Search results for dropdown (Feature 2)
  const searchResults = useMemo(() => {
    if (!searchQuery.trim() || searchQuery.length < 2) return [];
    const query = searchQuery.toLowerCase();
    return allFiles
      .filter(file => 
        file.name.toLowerCase().includes(query) || 
        file.path.toLowerCase().includes(query)
      )
      .slice(0, 8) // Limit to 8 results
      .map(file => ({
        ...file,
        matchType: file.name.toLowerCase().includes(query) ? "name" : "path",
      }));
  }, [allFiles, searchQuery]);

  // Breadcrumb path parts (Feature 1)
  const breadcrumbParts = useMemo(() => {
    if (!previewFile) return [];
    const parts = previewFile.split("/").filter(Boolean);
    return parts.map((part, idx) => ({
      name: part,
      path: parts.slice(0, idx + 1).join("/"),
      isLast: idx === parts.length - 1,
    }));
  }, [previewFile]);

  // Handle breadcrumb navigation
  const handleBreadcrumbClick = (path: string) => {
    // Expand the folder and scroll to it
    setExpandedFolders(prev => {
      const next = new Set(prev);
      next.add(path);
      return next;
    });
  };

  // Handle search result click (Feature 2)
  const handleSearchResultClick = (file: CodebaseFile) => {
    setPreviewFile(file.path);
    setSearchFocused(false);
    // Expand parent folders
    const parts = file.path.split("/");
    const foldersToExpand = new Set<string>();
    for (let i = 1; i < parts.length; i++) {
      foldersToExpand.add(parts.slice(0, i).join("/"));
    }
    setExpandedFolders(prev => new Set([...prev, ...foldersToExpand]));
  };

  // Jump to finding line (Feature 4)
  const handleJumpToFinding = (lineNum: number) => {
    setHighlightedFindingLine(lineNum);
    // Scroll to the line
    setTimeout(() => {
      const lineElement = document.getElementById(`code-line-${lineNum}`);
      if (lineElement && codePreviewRef.current) {
        lineElement.scrollIntoView({ behavior: "smooth", block: "center" });
      }
    }, 100);
    // Clear highlight after animation
    setTimeout(() => setHighlightedFindingLine(null), 2000);
  };
  
  // Copy code to clipboard (Feature: Copy Button)
  const handleCopyCode = useCallback(async () => {
    if (!fileContentQuery.data) return;
    
    const allCode = fileContentQuery.data.chunks
      .map(chunk => chunk.code)
      .join("\n\n// ... (chunk break) ...\n\n");
    
    try {
      await navigator.clipboard.writeText(allCode);
      setCodeCopied(true);
      setTimeout(() => setCodeCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy code:", err);
    }
  }, [fileContentQuery.data]);
  
  // Content search handler
  const handleContentSearch = useCallback(async () => {
    const query = contentSearchQuery.trim();
    if (query.length < 2) {
      setContentSearchResults(null);
      return;
    }
    
    setIsSearchingContent(true);
    try {
      const result = await api.searchCode(reportId, query);
      setContentSearchResults(result);
    } catch (err) {
      console.error("Content search failed:", err);
      setContentSearchResults(null);
    } finally {
      setIsSearchingContent(false);
    }
  }, [reportId, contentSearchQuery]);
  
  // AI Explanation handler
  const handleExplainCode = useCallback(async () => {
    if (!fileContentQuery.data || !previewFile || isExplaining) return;
    
    setIsExplaining(true);
    setShowExplanation(true);
    setExplanation(null);
    
    try {
      const allCode = fileContentQuery.data.chunks.map(c => c.code).join("\n");
      const result = await api.explainCode(
        reportId,
        previewFile,
        allCode,
        fileContentQuery.data.language || undefined
      );
      setExplanation(result);
    } catch (err) {
      console.error("Explain code failed:", err);
      setExplanation({ 
        file_path: previewFile, 
        explanation: "Failed to generate explanation. Please try again.", 
        findings_count: 0,
        error: "Request failed" 
      });
    } finally {
      setIsExplaining(false);
    }
  }, [reportId, previewFile, fileContentQuery.data, isExplaining]);

  // Severity filter
  const matchesSeverity = useCallback((node: CodebaseNode): boolean => {
    if (severityFilter === "all") return true;
    const findings = node.findings;
    switch (severityFilter) {
      case "critical": return findings.critical > 0;
      case "high": return findings.high > 0;
      case "medium": return findings.medium > 0;
      case "low": return findings.low > 0;
      default: return true;
    }
  }, [severityFilter]);

  // Language filter
  const matchesLanguage = useCallback((node: CodebaseNode): boolean => {
    if (selectedLanguages.size === 0) return true;
    if (node.type === "folder") {
      // Folder matches if any child matches
      return (node as CodebaseFolder).children.some(child => matchesLanguage(child));
    }
    return selectedLanguages.has(getEffectiveLanguage(node as CodebaseFile));
  }, [selectedLanguages]);

  // Filter tree recursively
  const filterTree = useCallback((nodes: CodebaseNode[]): CodebaseNode[] => {
    return nodes
      .map(node => {
        if (node.type === "folder") {
          const folder = node as CodebaseFolder;
          const filteredChildren = filterTree(folder.children);
          // Include folder if it has matching children or matches search itself
          if (filteredChildren.length > 0 || matchesSearch(node)) {
            return {
              ...folder,
              children: filteredChildren,
              file_count: filteredChildren.reduce((acc, c) => 
                acc + (c.type === "folder" ? (c as CodebaseFolder).file_count : 1), 0
              ),
            } as CodebaseFolder;
          }
          return null;
        }
        // File: check all filters
        if (matchesSearch(node) && matchesSeverity(node) && matchesLanguage(node)) {
          return node;
        }
        return null;
      })
      .filter((node): node is CodebaseNode => node !== null);
  }, [matchesSearch, matchesSeverity, matchesLanguage]);

  // Filtered tree
  const filteredTree = useMemo(() => {
    if (!codebaseQuery.data) return [];
    return filterTree(codebaseQuery.data.tree);
  }, [codebaseQuery.data, filterTree]);

  // Treemap data structure for interactive visualization
  const treemapData = useMemo(() => {
    if (!codebaseQuery.data) return [];
    
    // Build treemap from filtered files
    const buildTreemapNode = (nodes: CodebaseNode[]): any[] => {
      return nodes.map(node => {
        if (node.type === "folder") {
          const folder = node as CodebaseFolder;
          const children = buildTreemapNode(folder.children);
          // Only include folder if it has children
          if (children.length === 0) return null;
          return {
            name: folder.name,
            path: folder.path,
            children,
          };
        }
        // File node
        const file = node as CodebaseFile;
        // Apply filters
        if (!matchesSearch(file) || !matchesSeverity(file) || !matchesLanguage(file)) {
          return null;
        }
        const severity = file.findings.critical > 0 ? "critical"
          : file.findings.high > 0 ? "high"
          : file.findings.medium > 0 ? "medium"
          : file.findings.low > 0 ? "low"
          : "none";
        return {
          name: file.name,
          path: file.path,
          size: Math.max(file.lines || 1, 10), // Min size for visibility
          language: getEffectiveLanguage(file),
          lines: file.lines || 0,
          findings: file.findings.total,
          severity,
          file, // Keep reference for click handling
        };
      }).filter(Boolean);
    };
    
    // Flatten to group by language for a cleaner treemap
    const byLanguage: Record<string, any[]> = {};
    const collectByLanguage = (nodes: any[]) => {
      for (const node of nodes) {
        if (node.children) {
          collectByLanguage(node.children);
        } else {
          const lang = node.language;
          if (!byLanguage[lang]) byLanguage[lang] = [];
          byLanguage[lang].push(node);
        }
      }
    };
    collectByLanguage(buildTreemapNode(codebaseQuery.data.tree));
    
    return Object.entries(byLanguage)
      .map(([language, files]) => ({
        name: language,
        children: files,
      }))
      .filter(group => group.children.length > 0)
      .sort((a, b) => b.children.length - a.children.length);
  }, [codebaseQuery.data, matchesSearch, matchesSeverity, matchesLanguage]);

  // Custom treemap content
  const TreemapContent = (props: any) => {
    const { x, y, width, height, name, language, severity, findings, depth } = props;
    
    if (depth === 1) {
      // Language group header
      return (
        <g>
          <rect
            x={x}
            y={y}
            width={width}
            height={height}
            fill={alpha(getLanguageColor(name, theme), 0.2)}
            stroke={getLanguageColor(name, theme)}
            strokeWidth={2}
          />
          {width > 50 && height > 20 && (
            <>
              {/* Text shadow for readability */}
              <text
                x={x + 8}
                y={y + 18}
                fill={theme.palette.mode === "dark" ? "#000" : "#fff"}
                fontSize={14}
                fontWeight={700}
                fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
                dominantBaseline="middle"
                stroke={theme.palette.mode === "dark" ? "#000" : "#fff"}
                strokeWidth={3}
                paintOrder="stroke"
              >
                {name}
              </text>
              <text
                x={x + 8}
                y={y + 18}
                fill={getLanguageColor(name, theme)}
                fontSize={14}
                fontWeight={700}
                fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
                dominantBaseline="middle"
              >
                {name}
              </text>
            </>
          )}
        </g>
      );
    }
    
    // File cell
    const getSeverityColor = () => {
      switch (severity) {
        case "critical": return theme.palette.error.main;
        case "high": return "#f97316";
        case "medium": return theme.palette.warning.main;
        case "low": return theme.palette.info.main;
        default: return getLanguageColor(language, theme);
      }
    };
    
    // Heatmap mode: color based on finding density
    const getHeatmapColor = () => {
      if (findings === 0) return alpha(theme.palette.success.main, 0.3);
      if (findings === 1) return alpha(theme.palette.warning.light, 0.5);
      if (findings <= 3) return alpha(theme.palette.warning.main, 0.6);
      if (findings <= 5) return alpha("#f97316", 0.7);
      return alpha(theme.palette.error.main, 0.8);
    };
    
    const fillColor = heatmapMode
      ? getHeatmapColor()
      : (severity !== "none" 
        ? alpha(getSeverityColor(), 0.6) 
        : alpha(getLanguageColor(language, theme), 0.4));
    
    // Determine text color for best contrast
    const textColor = theme.palette.mode === "dark" ? "#fff" : "#000";
    const textShadowColor = theme.palette.mode === "dark" ? "#000" : "#fff";
    
    return (
      <g>
        <rect
          x={x}
          y={y}
          width={width}
          height={height}
          fill={fillColor}
          stroke={alpha(theme.palette.background.paper, 0.8)}
          strokeWidth={1}
          style={{ cursor: "pointer" }}
        />
        {width > 45 && height > 22 && (
          <>
            {/* Text shadow for readability */}
            <text
              x={x + 5}
              y={y + 14}
              fill={textShadowColor}
              fontSize={12}
              fontWeight={600}
              fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
              dominantBaseline="middle"
              stroke={textShadowColor}
              strokeWidth={3}
              paintOrder="stroke"
            >
              {name.length > Math.floor(width / 7) ? name.slice(0, Math.floor(width / 7)) + "…" : name}
            </text>
            <text
              x={x + 5}
              y={y + 14}
              fill={textColor}
              fontSize={12}
              fontWeight={600}
              fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
              dominantBaseline="middle"
            >
              {name.length > Math.floor(width / 7) ? name.slice(0, Math.floor(width / 7)) + "…" : name}
            </text>
          </>
        )}
        {findings > 0 && width > 35 && height > 35 && (
          <>
            <text
              x={x + 5}
              y={y + 28}
              fill={textShadowColor}
              fontSize={11}
              fontWeight={700}
              fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
              dominantBaseline="middle"
              stroke={textShadowColor}
              strokeWidth={3}
              paintOrder="stroke"
            >
              {findings} issues
            </text>
            <text
              x={x + 5}
              y={y + 28}
              fill={getSeverityColor()}
              fontSize={11}
              fontWeight={700}
              fontFamily="system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
              dominantBaseline="middle"
            >
              {findings} issues
            </text>
          </>
        )}
      </g>
    );
  };

  // Treemap tooltip
  const TreemapTooltipContent = ({ active, payload }: any) => {
    if (!active || !payload || !payload.length) return null;
    const data = payload[0].payload;
    if (!data.language) return null; // Skip language group tooltips
    
    return (
      <Paper sx={{ p: 1.5, maxWidth: 300 }}>
        <Typography variant="body2" fontWeight={700} fontFamily="monospace" sx={{ mb: 0.5 }}>
          {data.name}
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block">
          {data.path}
        </Typography>
        <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
          <Typography variant="caption">
            <strong>{data.lines?.toLocaleString()}</strong> lines
          </Typography>
          <Typography variant="caption">
            <strong>{data.language}</strong>
          </Typography>
          {data.findings > 0 && (
            <Typography variant="caption" color="error">
              <strong>{data.findings}</strong> findings
            </Typography>
          )}
        </Stack>
      </Paper>
    );
  };

  // Auto-expand folders when searching
  useEffect(() => {
    if (searchQuery.trim() && codebaseQuery.data) {
      const foldersToExpand = new Set<string>();
      const findMatchingPaths = (nodes: CodebaseNode[], parentPaths: string[] = []) => {
        for (const node of nodes) {
          const currentPaths = [...parentPaths, node.path];
          if (node.type === "folder") {
            findMatchingPaths((node as CodebaseFolder).children, currentPaths);
          } else if (matchesSearch(node)) {
            // Expand all parent folders
            parentPaths.forEach(p => foldersToExpand.add(p));
          }
        }
      };
      findMatchingPaths(codebaseQuery.data.tree);
      if (foldersToExpand.size > 0) {
        setExpandedFolders(foldersToExpand);
      }
    }
  }, [searchQuery, codebaseQuery.data, matchesSearch]);

  const handleToggleFolder = (path: string) => {
    setExpandedFolders((prev) => {
      const next = new Set(prev);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const handleExpandAll = () => {
    if (!codebaseQuery.data) return;
    const allFolders = new Set<string>();
    const collectFolders = (nodes: CodebaseNode[]) => {
      for (const node of nodes) {
        if (node.type === "folder") {
          allFolders.add(node.path);
          collectFolders((node as CodebaseFolder).children);
        }
      }
    };
    collectFolders(filteredTree);
    setExpandedFolders(allFolders);
  };

  const handleCollapseAll = () => {
    setExpandedFolders(new Set());
  };

  const handleShowMetadata = (file: CodebaseFile) => {
    setSelectedFile(file);
    setMetadataOpen(true);
  };

  const handleToggleLanguage = (lang: string) => {
    setSelectedLanguages(prev => {
      const next = new Set(prev);
      if (next.has(lang)) {
        next.delete(lang);
      } else {
        next.add(lang);
      }
      return next;
    });
  };

  const handleClearFilters = () => {
    setSearchQuery("");
    setSeverityFilter("all");
    setSelectedLanguages(new Set());
  };

  const hasActiveFilters = searchQuery.trim() || severityFilter !== "all" || selectedLanguages.size > 0;

  if (codebaseQuery.isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <Skeleton variant="rectangular" height={300} />
      </Box>
    );
  }

  if (codebaseQuery.isError) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        Failed to load codebase structure
      </Alert>
    );
  }

  if (!codebaseQuery.data || codebaseQuery.data.tree.length === 0) {
    return (
      <Paper
        sx={{
          p: 4,
          textAlign: "center",
          bgcolor: alpha(theme.palette.info.main, 0.05),
          border: `1px dashed ${alpha(theme.palette.info.main, 0.3)}`,
          borderRadius: 2,
        }}
      >
        <Typography color="text.secondary">
          No codebase data available. Run a scan first to analyze the codebase.
        </Typography>
      </Paper>
    );
  }

  const { summary } = codebaseQuery.data;
  const filteredFileCount = filteredTree.reduce((acc, node) => 
    acc + (node.type === "folder" ? (node as CodebaseFolder).file_count : 1), 0
  );

  return (
    <Box>
      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="h4" fontWeight={700} color="primary">
              {summary.total_files}
            </Typography>
            <Typography variant="caption" color="text.secondary">Files Analyzed</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.05) }}>
            <Typography variant="h4" fontWeight={700} color="secondary">
              {summary.total_lines.toLocaleString()}
            </Typography>
            <Typography variant="caption" color="text.secondary">Lines of Code</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
            <Typography variant="h4" fontWeight={700} sx={{ color: theme.palette.warning.main }}>
              {summary.languages.length}
            </Typography>
            <Typography variant="caption" color="text.secondary">Languages</Typography>
          </Paper>
        </Grid>
        <Grid item xs={6} sm={3}>
          <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.05) }}>
            <Typography variant="h4" fontWeight={700} color="error">
              {summary.total_findings}
            </Typography>
            <Typography variant="caption" color="text.secondary">Total Findings</Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* Language Statistics Dashboard (Quick Win #4) */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          bgcolor: alpha(theme.palette.background.paper, 0.5),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 2,
        }}
      >
        <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
          <Typography variant="subtitle2" fontWeight={700}>
            📊 Language Statistics
          </Typography>
          <Button 
            size="small" 
            onClick={() => setShowStats(!showStats)}
            sx={{ textTransform: "none" }}
          >
            {showStats ? "Hide" : "Show"}
          </Button>
        </Stack>
        
        <Collapse in={showStats}>
          <Grid container spacing={2}>
            {languageStats.slice(0, 8).map(({ language, files, lines, findings }) => {
              const isSelected = selectedLanguages.has(language);
              const percentage = Math.round((files / summary.total_files) * 100);
              return (
                <Grid item xs={6} sm={4} md={3} key={language}>
                  <Paper
                    onClick={() => handleToggleLanguage(language)}
                    sx={{
                      p: 1.5,
                      cursor: "pointer",
                      transition: "all 0.2s ease",
                      border: `2px solid ${isSelected ? getLanguageColor(language, theme) : "transparent"}`,
                      bgcolor: isSelected 
                        ? alpha(getLanguageColor(language, theme), 0.1) 
                        : alpha(theme.palette.background.default, 0.5),
                      "&:hover": {
                        bgcolor: alpha(getLanguageColor(language, theme), 0.15),
                        transform: "translateY(-2px)",
                      },
                    }}
                  >
                    <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
                      <Box
                        sx={{
                          width: 12,
                          height: 12,
                          borderRadius: "50%",
                          bgcolor: getLanguageColor(language, theme),
                        }}
                      />
                      <Typography variant="body2" fontWeight={600} sx={{ flex: 1 }}>
                        {language}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {percentage}%
                      </Typography>
                    </Stack>
                    <Box sx={{ mb: 1 }}>
                      <LinearProgress
                        variant="determinate"
                        value={percentage}
                        sx={{
                          height: 4,
                          borderRadius: 2,
                          bgcolor: alpha(getLanguageColor(language, theme), 0.2),
                          "& .MuiLinearProgress-bar": {
                            bgcolor: getLanguageColor(language, theme),
                          },
                        }}
                      />
                    </Box>
                    <Stack direction="row" justifyContent="space-between">
                      <Typography variant="caption" color="text.secondary">
                        {files} files
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {lines.toLocaleString()} lines
                      </Typography>
                      {findings > 0 && (
                        <Chip
                          size="small"
                          label={findings}
                          sx={{
                            height: 16,
                            fontSize: "0.65rem",
                            bgcolor: alpha(theme.palette.error.main, 0.15),
                            color: theme.palette.error.main,
                          }}
                        />
                      )}
                    </Stack>
                  </Paper>
                </Grid>
              );
            })}
          </Grid>
          {languageStats.length > 8 && (
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
              +{languageStats.length - 8} more languages
            </Typography>
          )}
        </Collapse>
      </Paper>

      {/* Search and Filters (Quick Wins #1, #2, #3) */}
      <Paper
        sx={{
          p: 2,
          mb: 3,
          bgcolor: alpha(theme.palette.background.paper, 0.5),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 2,
        }}
      >
        <Grid container spacing={2} alignItems="center">
          {/* Fuzzy File Search with Dropdown (Feature 2) */}
          <Grid item xs={12} md={5}>
            <Box ref={searchRef} sx={{ position: "relative" }}>
              <Stack direction="row" spacing={1} alignItems="center">
                {/* Search Mode Toggle */}
                <ToggleButtonGroup
                  value={searchMode}
                  exclusive
                  onChange={(_, value) => value && setSearchMode(value)}
                  size="small"
                  sx={{ flexShrink: 0 }}
                >
                  <ToggleButton value="filename" sx={{ px: 1, py: 0.5, fontSize: "0.7rem" }}>
                    <Tooltip title="Search file names">
                      <span>File</span>
                    </Tooltip>
                  </ToggleButton>
                  <ToggleButton value="content" sx={{ px: 1, py: 0.5, fontSize: "0.7rem" }}>
                    <Tooltip title="Search code content">
                      <span>Code</span>
                    </Tooltip>
                  </ToggleButton>
                </ToggleButtonGroup>
                
                <TextField
                  fullWidth
                  size="small"
                  placeholder={searchMode === "filename" ? "Search files... (e.g., auth, .py, service)" : "Search code... (e.g., password, API_KEY, def main)"}
                  value={searchMode === "filename" ? searchQuery : contentSearchQuery}
                  onChange={(e) => {
                    if (searchMode === "filename") {
                      setSearchQuery(e.target.value);
                    } else {
                      setContentSearchQuery(e.target.value);
                    }
                  }}
                  onFocus={() => setSearchFocused(true)}
                  onBlur={() => setTimeout(() => setSearchFocused(false), 200)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && searchMode === "content" && contentSearchQuery.trim()) {
                      handleContentSearch();
                    }
                  }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon />
                      </InputAdornment>
                    ),
                    endAdornment: (
                      <InputAdornment position="end">
                        {(searchMode === "filename" ? searchQuery : contentSearchQuery) && (
                          <IconButton 
                            size="small" 
                            onClick={() => {
                              if (searchMode === "filename") {
                                setSearchQuery("");
                              } else {
                                setContentSearchQuery("");
                                setContentSearchResults(null);
                              }
                            }}
                          >
                            <ClearIcon />
                          </IconButton>
                        )}
                        {searchMode === "content" && contentSearchQuery.trim() && (
                          <IconButton 
                            size="small" 
                            onClick={handleContentSearch}
                            disabled={isSearchingContent}
                            sx={{ color: "primary.main" }}
                          >
                            {isSearchingContent ? <CircularProgress size={16} /> : <SearchIcon />}
                          </IconButton>
                        )}
                      </InputAdornment>
                    ),
                  }}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      bgcolor: theme.palette.background.paper,
                    },
                  }}
                />
              </Stack>
              
              {/* Filename Search Results Dropdown (Feature 2) */}
              {searchMode === "filename" && searchFocused && searchResults.length > 0 && (
                <Paper
                  sx={{
                    position: "absolute",
                    top: "100%",
                    left: 0,
                    right: 0,
                    zIndex: 1000,
                    mt: 0.5,
                    maxHeight: 320,
                    overflow: "auto",
                    border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                    boxShadow: theme.shadows[8],
                  }}
                >
                  <Typography variant="caption" color="text.secondary" sx={{ p: 1, display: "block", borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}` }}>
                    {searchResults.length} file{searchResults.length !== 1 ? "s" : ""} found
                  </Typography>
                  {searchResults.map((file) => (
                    <Box
                      key={file.path}
                      onClick={() => handleSearchResultClick(file)}
                      sx={{
                        p: 1.5,
                        cursor: "pointer",
                        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.05)}`,
                        "&:hover": {
                          bgcolor: alpha(theme.palette.primary.main, 0.08),
                        },
                        "&:last-child": {
                          borderBottom: "none",
                        },
                      }}
                    >
                      <Stack direction="row" alignItems="center" spacing={1}>
                        <FileIcon />
                        <Box sx={{ flex: 1, minWidth: 0 }}>
                          <Typography variant="body2" fontWeight={600} noWrap>
                            {file.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
                            {file.path}
                          </Typography>
                        </Box>
                        <Chip
                          size="small"
                          label={getEffectiveLanguage(file)}
                          sx={{
                            height: 20,
                            fontSize: "0.65rem",
                            bgcolor: alpha(getLanguageColor(getEffectiveLanguage(file), theme), 0.15),
                            color: getLanguageColor(getEffectiveLanguage(file), theme),
                          }}
                        />
                        {file.findings.total > 0 && (
                          <Chip
                            size="small"
                            label={`${file.findings.total}`}
                            sx={{
                              height: 20,
                              fontSize: "0.65rem",
                              bgcolor: alpha(theme.palette.error.main, 0.15),
                              color: theme.palette.error.main,
                            }}
                          />
                        )}
                      </Stack>
                    </Box>
                  ))}
                </Paper>
              )}
              
              {/* Content Search Results Dropdown */}
              {searchMode === "content" && contentSearchResults && (
                <Paper
                  sx={{
                    position: "absolute",
                    top: "100%",
                    left: 0,
                    right: 0,
                    zIndex: 1000,
                    mt: 0.5,
                    maxHeight: 400,
                    overflow: "auto",
                    border: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                    boxShadow: theme.shadows[8],
                  }}
                >
                  <Stack 
                    direction="row" 
                    justifyContent="space-between" 
                    alignItems="center"
                    sx={{ 
                      p: 1, 
                      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                      bgcolor: alpha(theme.palette.primary.main, 0.05),
                    }}
                  >
                    <Typography variant="caption" color="text.secondary">
                      {contentSearchResults.total} match{contentSearchResults.total !== 1 ? "es" : ""} in {new Set(contentSearchResults.results.map(r => r.file_path)).size} file{new Set(contentSearchResults.results.map(r => r.file_path)).size !== 1 ? "s" : ""}
                    </Typography>
                    <IconButton size="small" onClick={() => setContentSearchResults(null)}>
                      <Box sx={{ fontSize: 16, display: "flex" }}><ClearIcon /></Box>
                    </IconButton>
                  </Stack>
                  {contentSearchResults.results.length === 0 ? (
                    <Typography variant="body2" color="text.secondary" sx={{ p: 2, textAlign: "center" }}>
                      No matches found for "{contentSearchResults.query}"
                    </Typography>
                  ) : (
                    contentSearchResults.results.map((match: CodeSearchMatch, index: number) => (
                      <Box
                        key={`${match.file_path}-${match.line}-${index}`}
                        onClick={() => {
                          // Navigate to file and line
                          const matchingFile = allFiles.find((f: CodebaseFile) => f.path === match.file_path);
                          if (matchingFile) {
                            setPreviewFile(matchingFile.path);
                            setTimeout(() => handleJumpToFinding(match.line), 300);
                          }
                          setContentSearchResults(null);
                        }}
                        sx={{
                          p: 1.5,
                          cursor: "pointer",
                          borderBottom: `1px solid ${alpha(theme.palette.divider, 0.05)}`,
                          "&:hover": {
                            bgcolor: alpha(theme.palette.primary.main, 0.08),
                          },
                          "&:last-child": {
                            borderBottom: "none",
                          },
                        }}
                      >
                        <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 0.5 }}>
                          <FileIcon />
                          <Typography variant="caption" fontWeight={600} noWrap sx={{ flex: 1 }}>
                            {match.file_path}
                          </Typography>
                          <Chip
                            size="small"
                            label={`L${match.line}`}
                            sx={{
                              height: 18,
                              fontSize: "0.6rem",
                              bgcolor: alpha(theme.palette.info.main, 0.15),
                              color: theme.palette.info.main,
                            }}
                          />
                        </Stack>
                        <Box
                          sx={{
                            p: 1,
                            bgcolor: alpha(theme.palette.background.default, 0.5),
                            borderRadius: 1,
                            fontFamily: "monospace",
                            fontSize: "0.75rem",
                            whiteSpace: "pre-wrap",
                            wordBreak: "break-all",
                            "& mark": {
                              bgcolor: alpha(theme.palette.warning.main, 0.4),
                              color: "inherit",
                              borderRadius: "2px",
                              px: 0.25,
                            },
                          }}
                          dangerouslySetInnerHTML={{
                            __html: match.content.replace(
                              new RegExp(`(${contentSearchResults.query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi'),
                              '<mark>$1</mark>'
                            ),
                          }}
                        />
                      </Box>
                    ))
                  )}
                </Paper>
              )}
            </Box>
          </Grid>

          {/* Severity Filter (Quick Win #2) */}
          <Grid item xs={12} md={5}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: "nowrap" }}>
                Severity:
              </Typography>
              <ToggleButtonGroup
                value={severityFilter}
                exclusive
                onChange={(_, value) => value && setSeverityFilter(value)}
                size="small"
                sx={{ flexWrap: "wrap" }}
              >
                <ToggleButton value="all" sx={{ px: 1.5, py: 0.5 }}>
                  All
                </ToggleButton>
                <ToggleButton 
                  value="critical" 
                  sx={{ 
                    px: 1.5, 
                    py: 0.5,
                    "&.Mui-selected": { 
                      bgcolor: alpha(theme.palette.error.main, 0.15),
                      color: theme.palette.error.main,
                    },
                  }}
                >
                  Critical
                </ToggleButton>
                <ToggleButton 
                  value="high"
                  sx={{ 
                    px: 1.5, 
                    py: 0.5,
                    "&.Mui-selected": { 
                      bgcolor: alpha("#f97316", 0.15),
                      color: "#f97316",
                    },
                  }}
                >
                  High
                </ToggleButton>
                <ToggleButton 
                  value="medium"
                  sx={{ 
                    px: 1.5, 
                    py: 0.5,
                    "&.Mui-selected": { 
                      bgcolor: alpha(theme.palette.warning.main, 0.15),
                      color: theme.palette.warning.main,
                    },
                  }}
                >
                  Medium
                </ToggleButton>
                <ToggleButton 
                  value="low"
                  sx={{ 
                    px: 1.5, 
                    py: 0.5,
                    "&.Mui-selected": { 
                      bgcolor: alpha(theme.palette.info.main, 0.15),
                      color: theme.palette.info.main,
                    },
                  }}
                >
                  Low
                </ToggleButton>
              </ToggleButtonGroup>
            </Stack>
          </Grid>

          {/* Clear Filters */}
          <Grid item xs={12} md={2}>
            {hasActiveFilters && (
              <Button
                size="small"
                variant="outlined"
                onClick={handleClearFilters}
                fullWidth
                sx={{ textTransform: "none" }}
              >
                Clear Filters
              </Button>
            )}
          </Grid>
        </Grid>

        {/* Language Filter Chips (Quick Win #3) */}
        {selectedLanguages.size > 0 && (
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary" sx={{ mr: 1 }}>
              Filtered by language:
            </Typography>
            {Array.from(selectedLanguages).map(lang => (
              <Chip
                key={lang}
                label={lang}
                size="small"
                onDelete={() => handleToggleLanguage(lang)}
                sx={{
                  mr: 0.5,
                  mb: 0.5,
                  bgcolor: alpha(getLanguageColor(lang, theme), 0.15),
                  color: getLanguageColor(lang, theme),
                  fontWeight: 600,
                }}
              />
            ))}
          </Box>
        )}

        {/* Filter Results Summary */}
        {hasActiveFilters && (
          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
            Showing {filteredFileCount} of {summary.total_files} files
          </Typography>
        )}
      </Paper>

      {/* View Mode & Tree Controls */}
      <Stack direction="row" spacing={1} sx={{ mb: 2 }} alignItems="center" justifyContent="space-between">
        <Stack direction="row" spacing={1} alignItems="center">
          {viewMode === "tree" && (
            <>
              <Button size="small" variant="outlined" onClick={handleExpandAll}>
                Expand All
              </Button>
              <Button size="small" variant="outlined" onClick={handleCollapseAll}>
                Collapse All
              </Button>
              {showCodePreview && (
                <Button 
                  size="small" 
                  variant="contained"
                  onClick={() => setShowCodePreview(false)}
                  sx={{ ml: 1 }}
                >
                  Hide Code Preview
                </Button>
              )}
            </>
          )}
        </Stack>
        <ToggleButtonGroup
          value={viewMode}
          exclusive
          onChange={(_, value) => value && setViewMode(value)}
          size="small"
        >
          <ToggleButton value="tree" sx={{ px: 2, py: 0.5 }}>
            🌲 Tree
          </ToggleButton>
          <ToggleButton value="treemap" sx={{ px: 2, py: 0.5 }}>
            📊 Treemap
          </ToggleButton>
          <ToggleButton value="dependencies" sx={{ px: 2, py: 0.5 }}>
            🔗 Dependencies
          </ToggleButton>
          <ToggleButton 
            value="diff" 
            sx={{ px: 2, py: 0.5 }}
            disabled={comparableReports.length === 0}
          >
            📈 Diff {comparableReports.length > 0 && `(${comparableReports.length})`}
          </ToggleButton>
          <ToggleButton value="todos" sx={{ px: 2, py: 0.5 }}>
            📝 TODOs
          </ToggleButton>
          <ToggleButton value="secrets" sx={{ px: 2, py: 0.5 }}>
            🔐 Secrets
          </ToggleButton>
          <ToggleButton value="diagram" sx={{ px: 2, py: 0.5 }}>
            🕸️ Diagram
          </ToggleButton>
          <ToggleButton value="cves" sx={{ px: 2, py: 0.5 }}>
            🛡️ CVEs
          </ToggleButton>
        </ToggleButtonGroup>
        
        {/* Heatmap Toggle for Treemap */}
        {viewMode === "treemap" && (
          <Tooltip title="Toggle heatmap mode - shows finding density">
            <Button
              size="small"
              variant={heatmapMode ? "contained" : "outlined"}
              onClick={() => setHeatmapMode(!heatmapMode)}
              sx={{ 
                textTransform: "none", 
                minWidth: "auto",
                bgcolor: heatmapMode ? alpha(theme.palette.error.main, 0.8) : undefined,
                "&:hover": {
                  bgcolor: heatmapMode ? theme.palette.error.main : undefined,
                },
              }}
            >
              🔥 Heatmap
            </Button>
          </Tooltip>
        )}
      </Stack>

      {/* File Tree View with Optional Code Preview */}
      {viewMode === "tree" && (
        <Stack spacing={2}>
          {/* File Tree */}
          <Paper
            sx={{
              p: 2,
              bgcolor: alpha(theme.palette.background.paper, 0.5),
              border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
              borderRadius: 2,
              maxHeight: showCodePreview ? 350 : 600,
              overflow: "auto",
            }}
          >
            {filteredTree.length === 0 ? (
              <Box sx={{ p: 3, textAlign: "center" }}>
                <Typography color="text.secondary">
                  No files match the current filters.
                </Typography>
                <Button 
                  size="small" 
                  onClick={handleClearFilters}
                  sx={{ mt: 1, textTransform: "none" }}
                >
                  Clear Filters
                </Button>
              </Box>
            ) : (
              filteredTree.map((node) => (
                <TreeNode
                  key={node.path}
                  node={node}
                  depth={0}
                  expandedFolders={expandedFolders}
                  onToggleFolder={handleToggleFolder}
                  onShowMetadata={handleShowMetadata}
                  searchQuery={searchQuery}
                  onFileClick={showCodePreview ? (file) => setPreviewFile(file.path) : undefined}
                  selectedPath={previewFile}
                />
              ))
            )}
          </Paper>
          
          {/* Code Preview Panel - Full Width Below Tree */}
          {showCodePreview && (
            <Paper
              sx={{
                p: 2,
                bgcolor: alpha(theme.palette.background.paper, 0.5),
                border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                borderRadius: 2,
              }}
            >
              {!previewFile ? (
                <Box sx={{ p: 4, textAlign: "center" }}>
                  <Typography color="text.secondary">
                    ☝️ Click a file in the tree above to preview its code
                  </Typography>
                </Box>
              ) : fileContentQuery.isLoading ? (
                <Box sx={{ p: 4, textAlign: "center" }}>
                  <CircularProgress size={24} />
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                    Loading file...
                  </Typography>
                </Box>
              ) : fileContentQuery.isError ? (
                <Alert severity="error">Failed to load file content</Alert>
              ) : fileContentQuery.data ? (
                <Box>
                  {/* Breadcrumb Navigation (Feature 1) */}
                  <Stack direction="row" alignItems="center" spacing={0.5} sx={{ mb: 2, flexWrap: "wrap" }}>
                    <IconButton 
                      size="small" 
                      onClick={() => setPreviewFile(null)}
                      sx={{ p: 0.5 }}
                    >
                      <HomeIcon />
                    </IconButton>
                    {breadcrumbParts.map((part, idx) => (
                      <Stack key={part.path} direction="row" alignItems="center" spacing={0.5}>
                        <NavigateNextIcon />
                        {part.isLast ? (
                          <Chip
                            size="small"
                            label={part.name}
                            sx={{
                              fontWeight: 600,
                              bgcolor: alpha(getLanguageColor(fileContentQuery.data?.language || "", theme), 0.15),
                              color: getLanguageColor(fileContentQuery.data?.language || "", theme),
                            }}
                          />
                        ) : (
                          <Button
                            size="small"
                            onClick={() => handleBreadcrumbClick(part.path)}
                            sx={{ 
                              textTransform: "none", 
                              minWidth: "auto", 
                              px: 1,
                              py: 0.25,
                              fontSize: "0.8rem",
                              color: "text.secondary",
                              "&:hover": { color: "primary.main" },
                            }}
                          >
                            {part.name}
                          </Button>
                        )}
                      </Stack>
                    ))}
                    <Box sx={{ flex: 1 }} />
                    
                    {/* File Trends Sparkline */}
                    {fileTrendsQuery.data && fileTrendsQuery.data.trends.length > 1 && (
                      <Tooltip title={`Finding trends over ${fileTrendsQuery.data.trends.length} scans`}>
                        <Box sx={{ width: 60, height: 24, mr: 1 }}>
                          <SparklineContainer width="100%" height="100%">
                            <LineChart data={fileTrendsQuery.data.trends}>
                              <Line 
                                type="monotone" 
                                dataKey="finding_count" 
                                stroke={theme.palette.warning.main}
                                strokeWidth={2}
                                dot={false}
                              />
                            </LineChart>
                          </SparklineContainer>
                        </Box>
                      </Tooltip>
                    )}
                    
                    <Typography variant="caption" color="text.secondary">
                      {fileContentQuery.data.total_lines} lines
                    </Typography>
                    
                    {/* AI Explain Button */}
                    <Tooltip title={isExplaining ? "Analyzing..." : "Explain with AI"}>
                      <IconButton 
                        size="small" 
                        onClick={handleExplainCode}
                        disabled={isExplaining}
                        sx={{ 
                          color: showExplanation ? "primary.main" : "text.secondary",
                          transition: "color 0.2s",
                          animation: isExplaining ? `${fadeIn} 0.5s ease infinite alternate` : "none",
                        }}
                      >
                        {isExplaining ? <CircularProgress size={18} /> : <AIIcon />}
                      </IconButton>
                    </Tooltip>
                    
                    {/* Copy Code Button */}
                    <Tooltip title={codeCopied ? "Copied!" : "Copy code"}>
                      <IconButton 
                        size="small" 
                        onClick={handleCopyCode}
                        sx={{ 
                          color: codeCopied ? "success.main" : "text.secondary",
                          transition: "color 0.2s",
                        }}
                      >
                        {codeCopied ? <CheckIcon /> : <CopyIcon />}
                      </IconButton>
                    </Tooltip>
                    
                    <IconButton 
                      size="small" 
                      onClick={() => setPreviewFile(null)}
                      sx={{ color: "text.secondary" }}
                    >
                      <CloseIcon />
                    </IconButton>
                  </Stack>
                  
                  {/* Findings Summary with Jump Links (Feature 4) */}
                  {fileContentQuery.data.findings.length > 0 && (
                    <Alert 
                      severity="warning" 
                      sx={{ mb: 2 }}
                      action={
                        <Stack direction="row" spacing={0.5} alignItems="center">
                          {fileContentQuery.data.findings.slice(0, 5).map((f, i) => (
                            <Tooltip key={i} title={`Jump to line ${f.line}: ${f.type}`}>
                              <Chip
                                size="small"
                                label={`L${f.line}`}
                                onClick={() => handleJumpToFinding(f.line)}
                                icon={<JumpIcon />}
                                sx={{
                                  cursor: "pointer",
                                  height: 22,
                                  fontSize: "0.7rem",
                                  bgcolor: alpha(
                                    f.severity === "critical" ? theme.palette.error.main :
                                    f.severity === "high" ? "#f97316" :
                                    f.severity === "medium" ? theme.palette.warning.main :
                                    theme.palette.info.main,
                                    0.2
                                  ),
                                  "&:hover": { 
                                    bgcolor: alpha(
                                      f.severity === "critical" ? theme.palette.error.main :
                                      f.severity === "high" ? "#f97316" :
                                      f.severity === "medium" ? theme.palette.warning.main :
                                      theme.palette.info.main,
                                      0.35
                                    ),
                                  },
                                }}
                              />
                            </Tooltip>
                          ))}
                          {fileContentQuery.data.findings.length > 5 && (
                            <Typography variant="caption" color="text.secondary">
                              +{fileContentQuery.data.findings.length - 5} more
                            </Typography>
                          )}
                        </Stack>
                      }
                    >
                      {fileContentQuery.data.findings.length} finding(s) in this file - click to jump
                    </Alert>
                  )}
                  
                  {fileContentQuery.data.source === "chunks" && fileContentQuery.data.chunks.length > 1 && (
                    <Alert severity="info" sx={{ mb: 2, py: 0.5 }} icon={false}>
                      <Typography variant="caption">
                        📝 Showing {fileContentQuery.data.chunks.length} indexed code sections. 
                        Source file not available on disk.
                      </Typography>
                    </Alert>
                  )}
                  
                  {/* Code with Syntax Highlighting (Feature 3) */}
                  <Box
                    ref={codePreviewRef}
                    sx={{
                      bgcolor: "#1e1e1e",
                      borderRadius: 1,
                      overflow: "auto",
                      maxHeight: 500,
                      "& pre": { margin: 0 },
                      "& .token.comment": { color: "#6a9955" },
                      "& .token.string": { color: "#ce9178" },
                      "& .token.keyword": { color: "#569cd6" },
                      "& .token.function": { color: "#dcdcaa" },
                      "& .token.number": { color: "#b5cea8" },
                      "& .token.operator": { color: "#d4d4d4" },
                      "& .token.class-name": { color: "#4ec9b0" },
                      "& .token.punctuation": { color: "#d4d4d4" },
                      "& .token.property": { color: "#9cdcfe" },
                      "& .token.boolean": { color: "#569cd6" },
                      "& .token.builtin": { color: "#4ec9b0" },
                    }}
                  >
                    {fileContentQuery.data.chunks.map((chunk, idx) => (
                      <Box key={idx} sx={{ position: "relative" }}>
                        <pre
                          style={{
                            margin: 0,
                            padding: "12px 16px",
                            fontSize: "0.85rem",
                            fontFamily: "'Fira Code', Monaco, Consolas, monospace",
                            lineHeight: 1.6,
                            whiteSpace: "pre",
                            overflowX: "auto",
                            color: "#d4d4d4",
                          }}
                        >
                          {chunk.code.split("\n").map((line, lineIdx) => {
                            const lineNum = chunk.start_line + lineIdx;
                            const finding = fileContentQuery.data!.findings.find(f => f.line === lineNum);
                            const isHighlighted = highlightedFindingLine === lineNum;
                            const highlightedHtml = highlightCode(line, fileContentQuery.data?.language || "");
                            return (
                              <Box
                                key={lineIdx}
                                id={`code-line-${lineNum}`}
                                component="div"
                                sx={{
                                  display: "flex",
                                  bgcolor: isHighlighted 
                                    ? alpha(theme.palette.primary.main, 0.3)
                                    : finding 
                                      ? alpha(
                                          finding.severity === "critical" ? theme.palette.error.main :
                                          finding.severity === "high" ? "#f97316" :
                                          finding.severity === "medium" ? theme.palette.warning.main :
                                          theme.palette.info.main,
                                          0.15
                                        )
                                      : "transparent",
                                  transition: "background-color 0.3s ease",
                                  "&:hover": {
                                    bgcolor: alpha(theme.palette.primary.main, 0.1),
                                  },
                                }}
                              >
                                <Box
                                  component="span"
                                  sx={{
                                    minWidth: 50,
                                    pr: 2,
                                    color: finding ? (
                                      finding.severity === "critical" ? theme.palette.error.main :
                                      finding.severity === "high" ? "#f97316" :
                                      theme.palette.warning.main
                                    ) : "#6e7681",
                                    fontWeight: finding ? 700 : 400,
                                    textAlign: "right",
                                    userSelect: "none",
                                    borderRight: `1px solid ${alpha(theme.palette.divider, 0.2)}`,
                                    mr: 2,
                                  }}
                                >
                                  {lineNum}
                                </Box>
                                <Box 
                                  component="span" 
                                  sx={{ flex: 1 }}
                                  dangerouslySetInnerHTML={{ __html: highlightedHtml || " " }}
                                />
                                {finding && (
                                  <Tooltip title={`${finding.type}: ${finding.summary}`}>
                                    <Chip
                                      size="small"
                                      label={finding.severity}
                                      onClick={() => handleJumpToFinding(lineNum)}
                                      sx={{
                                        ml: 1,
                                        height: 18,
                                        fontSize: "0.65rem",
                                        cursor: "pointer",
                                        bgcolor: alpha(
                                          finding.severity === "critical" ? theme.palette.error.main :
                                          finding.severity === "high" ? "#f97316" :
                                          finding.severity === "medium" ? theme.palette.warning.main :
                                          theme.palette.info.main,
                                          0.3
                                        ),
                                        "&:hover": {
                                          bgcolor: alpha(
                                            finding.severity === "critical" ? theme.palette.error.main :
                                            finding.severity === "high" ? "#f97316" :
                                            finding.severity === "medium" ? theme.palette.warning.main :
                                            theme.palette.info.main,
                                            0.5
                                          ),
                                        },
                                      }}
                                    />
                                  </Tooltip>
                                )}
                              </Box>
                            );
                          })}
                        </pre>
                      </Box>
                    ))}
                  </Box>
                </Box>
              ) : null}
              
              {/* AI Explanation Panel */}
              <Collapse in={showExplanation && explanation !== null}>
                <Box
                  sx={{
                    mt: 2,
                    p: 2,
                    bgcolor: alpha(theme.palette.primary.main, 0.05),
                    border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
                    borderRadius: 2,
                  }}
                >
                  <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
                    <Stack direction="row" alignItems="center" spacing={1}>
                      <AIIcon />
                      <Typography variant="subtitle2" fontWeight={600} color="primary.main">
                        AI Code Analysis
                      </Typography>
                    </Stack>
                    <IconButton 
                      size="small" 
                      onClick={() => setShowExplanation(false)}
                      sx={{ color: "text.secondary" }}
                    >
                      <CloseIcon />
                    </IconButton>
                  </Stack>
                  {explanation && (
                    <Box
                      sx={{
                        "& h1, & h2, & h3": {
                          fontSize: "1rem",
                          fontWeight: 600,
                          color: "primary.main",
                          mt: 2,
                          mb: 1,
                        },
                        "& h1:first-of-type, & h2:first-of-type": {
                          mt: 0,
                        },
                        "& p": {
                          fontSize: "0.875rem",
                          mb: 1,
                          lineHeight: 1.6,
                        },
                        "& ul, & ol": {
                          pl: 2,
                          mb: 1,
                        },
                        "& li": {
                          fontSize: "0.875rem",
                          mb: 0.5,
                        },
                        "& code": {
                          fontFamily: "monospace",
                          fontSize: "0.8rem",
                          bgcolor: alpha(theme.palette.background.default, 0.8),
                          px: 0.5,
                          py: 0.25,
                          borderRadius: 0.5,
                        },
                        "& pre": {
                          bgcolor: alpha(theme.palette.background.default, 0.8),
                          p: 1.5,
                          borderRadius: 1,
                          overflow: "auto",
                          "& code": {
                            bgcolor: "transparent",
                            p: 0,
                          },
                        },
                        "& strong": {
                          color: "warning.main",
                        },
                      }}
                    >
                      <ReactMarkdown>{explanation.explanation}</ReactMarkdown>
                    </Box>
                  )}
                </Box>
              </Collapse>
            </Paper>
          )}
        </Stack>
      )}

      {/* Interactive Treemap View */}
      {viewMode === "treemap" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          {treemapData.length === 0 ? (
            <Box sx={{ p: 3, textAlign: "center" }}>
              <Typography color="text.secondary">
                No files match the current filters.
              </Typography>
              <Button 
                size="small" 
                onClick={handleClearFilters}
                sx={{ mt: 1, textTransform: "none" }}
              >
                Clear Filters
              </Button>
            </Box>
          ) : (
            <>
              <Box sx={{ mb: 2 }}>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>
                  📊 Codebase Visualization
                </Typography>
                <Typography variant="caption" color="text.secondary" display="block">
                  Each rectangle represents a file. Size = lines of code. Grouped by language.
                  Files with vulnerabilities are highlighted in red/orange.
                </Typography>
              </Box>
              <Box sx={{ height: 500, border: `1px solid ${alpha(theme.palette.divider, 0.2)}`, borderRadius: 1 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <Treemap
                    data={treemapData}
                    dataKey="size"
                    aspectRatio={4 / 3}
                    stroke={theme.palette.divider}
                    fill={theme.palette.primary.main}
                    content={<TreemapContent />}
                    onClick={(data: any) => {
                      if (data?.file) {
                        handleShowMetadata(data.file);
                      }
                    }}
                  >
                    <RechartsTooltip content={<TreemapTooltipContent />} />
                  </Treemap>
                </ResponsiveContainer>
              </Box>
              <Stack direction="row" spacing={2} sx={{ mt: 2 }} flexWrap="wrap" alignItems="center">
                <Typography variant="caption" color="text.secondary" fontWeight={600}>
                  Legend:
                </Typography>
                {heatmapMode ? (
                  // Heatmap legend
                  <>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.success.main, 0.3) }} />
                      <Typography variant="caption">0 findings</Typography>
                    </Stack>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.warning.light, 0.5) }} />
                      <Typography variant="caption">1 finding</Typography>
                    </Stack>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.warning.main, 0.6) }} />
                      <Typography variant="caption">2-3 findings</Typography>
                    </Stack>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha("#f97316", 0.7) }} />
                      <Typography variant="caption">4-5 findings</Typography>
                    </Stack>
                    <Stack direction="row" alignItems="center" spacing={0.5}>
                      <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.error.main, 0.8) }} />
                      <Typography variant="caption">6+ findings</Typography>
                    </Stack>
                  </>
                ) : (
                  // Normal legend
                  <>
                    {languageStats.slice(0, 6).map(({ language }) => (
                      <Stack key={language} direction="row" alignItems="center" spacing={0.5}>
                        <Box
                          sx={{
                            width: 14,
                            height: 14,
                            borderRadius: 1,
                            bgcolor: alpha(getLanguageColor(language, theme), 0.5),
                            border: `2px solid ${getLanguageColor(language, theme)}`,
                          }}
                        />
                        <Typography variant="caption">{language}</Typography>
                      </Stack>
                    ))}
                    <Box sx={{ borderLeft: `1px solid ${theme.palette.divider}`, pl: 2, ml: 1 }}>
                      <Stack direction="row" spacing={1}>
                        <Stack direction="row" alignItems="center" spacing={0.5}>
                          <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.error.main, 0.7) }} />
                          <Typography variant="caption">Critical</Typography>
                        </Stack>
                        <Stack direction="row" alignItems="center" spacing={0.5}>
                          <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha("#f97316", 0.7) }} />
                          <Typography variant="caption">High</Typography>
                        </Stack>
                        <Stack direction="row" alignItems="center" spacing={0.5}>
                          <Box sx={{ width: 14, height: 14, borderRadius: 1, bgcolor: alpha(theme.palette.warning.main, 0.7) }} />
                          <Typography variant="caption">Medium</Typography>
                        </Stack>
                      </Stack>
                    </Box>
                  </>
                )}
              </Stack>
            </>
          )}
        </Paper>
      )}

      {/* Dependencies View */}
      {viewMode === "dependencies" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          {dependenciesQuery.isLoading ? (
            <Box sx={{ p: 4, textAlign: "center" }}>
              <CircularProgress size={32} />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Loading dependencies...
              </Typography>
            </Box>
          ) : dependenciesQuery.isError ? (
            <Alert severity="error">Failed to load dependency information</Alert>
          ) : dependenciesQuery.data ? (
            <Box>
              {/* Summary Cards */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
                    <Typography variant="h4" fontWeight={700} color="primary">
                      {dependenciesQuery.data.summary.total_external}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">External Packages</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.secondary.main, 0.05) }}>
                    <Typography variant="h4" fontWeight={700} color="secondary">
                      {dependenciesQuery.data.summary.ecosystems.length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Ecosystems</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
                    <Typography variant="h4" fontWeight={700} sx={{ color: theme.palette.warning.main }}>
                      {dependenciesQuery.data.summary.total_internal_edges}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Internal Imports</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                    <Typography variant="h4" fontWeight={700} color="error">
                      {dependenciesQuery.data.external_dependencies.filter(d => d.has_vulnerabilities).length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Vulnerable Packages</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* External Dependencies Table */}
              <Typography variant="subtitle2" sx={{ mb: 2 }}>
                📦 External Dependencies
              </Typography>
              
              {dependenciesQuery.data.external_dependencies.length === 0 ? (
                <Typography color="text.secondary" sx={{ mb: 3 }}>
                  No external dependencies found in manifest files.
                </Typography>
              ) : (
                <TableContainer component={Paper} sx={{ mb: 3, maxHeight: 300 }}>
                  <Table size="small" stickyHeader>
                    <TableHead>
                      <TableRow>
                        <TableCell>Package</TableCell>
                        <TableCell>Version</TableCell>
                        <TableCell>Ecosystem</TableCell>
                        <TableCell>Status</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {dependenciesQuery.data.external_dependencies.slice(0, 50).map((dep, idx) => (
                        <TableRow key={idx} sx={{ "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) } }}>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace" fontWeight={500}>
                              {dep.name}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Typography variant="body2" fontFamily="monospace" color="text.secondary">
                              {dep.version || "any"}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            <Chip 
                              size="small" 
                              label={dep.ecosystem}
                              sx={{ 
                                fontSize: "0.7rem",
                                bgcolor: alpha(getLanguageColor(dep.ecosystem, theme), 0.15),
                              }}
                            />
                          </TableCell>
                          <TableCell>
                            {dep.has_vulnerabilities ? (
                              <Chip 
                                size="small" 
                                label="⚠️ Vulnerable"
                                sx={{ 
                                  fontSize: "0.65rem",
                                  bgcolor: alpha(theme.palette.error.main, 0.15),
                                  color: theme.palette.error.main,
                                }}
                              />
                            ) : (
                              <Typography variant="caption" color="success.main">✓ OK</Typography>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
              )}

              {/* Internal Imports Graph Placeholder */}
              {dependenciesQuery.data.internal_imports.length > 0 && (
                <>
                  <Typography variant="subtitle2" sx={{ mb: 2 }}>
                    🔗 Internal File Imports
                  </Typography>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), maxHeight: 250, overflow: "auto" }}>
                    <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                      {dependenciesQuery.data.internal_imports.length} import relationships detected
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                      {dependenciesQuery.data.internal_imports.slice(0, 30).map((imp, idx) => (
                        <Chip
                          key={idx}
                          size="small"
                          label={
                            <Typography variant="caption" fontFamily="monospace" sx={{ fontSize: "0.65rem" }}>
                              {imp.source.split("/").pop()} → {imp.target.split("/").pop()}
                            </Typography>
                          }
                          sx={{ 
                            bgcolor: alpha(theme.palette.info.main, 0.1),
                            border: `1px solid ${alpha(theme.palette.info.main, 0.3)}`,
                          }}
                        />
                      ))}
                      {dependenciesQuery.data.internal_imports.length > 30 && (
                        <Chip
                          size="small"
                          label={`+${dependenciesQuery.data.internal_imports.length - 30} more`}
                          sx={{ bgcolor: alpha(theme.palette.text.secondary, 0.1) }}
                        />
                      )}
                    </Box>
                  </Paper>
                </>
              )}
            </Box>
          ) : null}
        </Paper>
      )}

      {/* Diff View (Feature 5) */}
      {viewMode === "diff" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          {/* Report Selector */}
          <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 3 }}>
            <Typography variant="subtitle2">Compare with:</Typography>
            <FormControl size="small" sx={{ minWidth: 300 }}>
              <InputLabel>Select a previous scan</InputLabel>
              <Select
                value={compareReportId || ""}
                label="Select a previous scan"
                onChange={(e) => setCompareReportId(Number(e.target.value) || null)}
              >
                {comparableReports.map((r) => (
                  <MenuItem key={r.id} value={r.id}>
                    Scan #{r.id} - {new Date(r.created_at).toLocaleString()}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Stack>

          {!compareReportId ? (
            <Box sx={{ p: 4, textAlign: "center" }}>
              <Typography color="text.secondary">
                Select a previous scan to compare findings
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ mt: 1 }}>
                {comparableReports.length > 0 
                  ? `${comparableReports.length} scan(s) available for comparison`
                  : "No other scans available for this project"
                }
              </Typography>
            </Box>
          ) : diffQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress size={40} />
              <Typography sx={{ ml: 2 }}>Comparing scans...</Typography>
            </Box>
          ) : diffQuery.isError ? (
            <Alert severity="error">Failed to compare scans</Alert>
          ) : diffQuery.data ? (
            <Box>
              {/* Summary Cards */}
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} md={3}>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.1), textAlign: "center" }}>
                    <Typography variant="h4" color="error.main" fontWeight="bold">
                      {diffQuery.data.new_findings.length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">New Findings</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.1), textAlign: "center" }}>
                    <Typography variant="h4" color="success.main" fontWeight="bold">
                      {diffQuery.data.fixed_findings.length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Fixed Findings</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Paper sx={{ 
                    p: 2, 
                    bgcolor: alpha(
                      diffQuery.data.new_findings.length > diffQuery.data.fixed_findings.length 
                        ? theme.palette.warning.main 
                        : theme.palette.info.main, 
                      0.1
                    ), 
                    textAlign: "center" 
                  }}>
                    <Typography 
                      variant="h4" 
                      fontWeight="bold"
                      color={
                        diffQuery.data.new_findings.length - diffQuery.data.fixed_findings.length > 0
                          ? "error.main"
                          : diffQuery.data.new_findings.length - diffQuery.data.fixed_findings.length < 0
                          ? "success.main"
                          : "text.primary"
                      }
                    >
                      {diffQuery.data.new_findings.length - diffQuery.data.fixed_findings.length > 0 ? "+" : ""}
                      {diffQuery.data.new_findings.length - diffQuery.data.fixed_findings.length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Net Change</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} md={3}>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.1), textAlign: "center" }}>
                    <Typography variant="h4" color="info.main" fontWeight="bold">
                      {diffQuery.data.changed_files.length}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Files Changed</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* Severity Changes Summary */}
              {diffQuery.data.summary?.severity_changes && (
                <Box sx={{ mb: 3, p: 2, bgcolor: alpha(theme.palette.background.default, 0.5), borderRadius: 1 }}>
                  <Typography variant="subtitle2" sx={{ mb: 1 }}>Severity Breakdown</Typography>
                  <Stack direction="row" spacing={2} flexWrap="wrap">
                    {Object.entries(diffQuery.data.summary.severity_changes).map(([severity, changes]) => (
                      <Chip
                        key={severity}
                        size="small"
                        label={
                          <Typography variant="caption">
                            {severity}: {(changes as { new: number; fixed: number }).new > 0 && <span style={{ color: theme.palette.error.main }}>+{(changes as { new: number; fixed: number }).new}</span>}
                            {(changes as { new: number; fixed: number }).new > 0 && (changes as { new: number; fixed: number }).fixed > 0 && " / "}
                            {(changes as { new: number; fixed: number }).fixed > 0 && <span style={{ color: theme.palette.success.main }}>-{(changes as { new: number; fixed: number }).fixed}</span>}
                          </Typography>
                        }
                        sx={{
                          bgcolor: alpha(
                            severity === "critical" ? theme.palette.error.dark :
                            severity === "high" ? theme.palette.error.main :
                            severity === "medium" ? theme.palette.warning.main :
                            severity === "low" ? theme.palette.info.main :
                            theme.palette.grey[500],
                            0.2
                          )
                        }}
                      />
                    ))}
                  </Stack>
                </Box>
              )}

              {/* New Findings */}
              {diffQuery.data.new_findings.length > 0 && (
                <Box sx={{ mb: 3 }}>
                  <Typography variant="subtitle2" sx={{ mb: 2, color: "error.main" }}>
                    🆕 New Findings ({diffQuery.data.new_findings.length})
                  </Typography>
                  <Stack spacing={1}>
                    {diffQuery.data.new_findings.map((finding, idx) => (
                      <Paper 
                        key={idx}
                        sx={{ 
                          p: 1.5, 
                          bgcolor: alpha(theme.palette.error.main, 0.05),
                          border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                          "&:hover": { bgcolor: alpha(theme.palette.error.main, 0.1) }
                        }}
                      >
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Chip 
                            size="small" 
                            label={finding.severity}
                            sx={{ 
                              bgcolor: alpha(
                                finding.severity === "critical" ? theme.palette.error.dark :
                                finding.severity === "high" ? theme.palette.error.main :
                                finding.severity === "medium" ? theme.palette.warning.main :
                                theme.palette.info.main,
                                0.2
                              ),
                              fontSize: "0.65rem",
                              height: 20,
                            }}
                          />
                          <Typography variant="body2" fontWeight="medium">
                            {finding.type.startsWith("agentic-") && "🤖 "}
                            {finding.type.startsWith("agentic-") ? finding.type.replace("agentic-", "") : finding.type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                            {finding.file_path}{finding.start_line ? `:${finding.start_line}` : ""}
                          </Typography>
                        </Stack>
                        {finding.summary && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block" }}>
                            {finding.summary}
                          </Typography>
                        )}
                      </Paper>
                    ))}
                  </Stack>
                </Box>
              )}

              {/* Fixed Findings */}
              {diffQuery.data.fixed_findings.length > 0 && (
                <Box>
                  <Typography variant="subtitle2" sx={{ mb: 2, color: "success.main" }}>
                    ✅ Fixed Findings ({diffQuery.data.fixed_findings.length})
                  </Typography>
                  <Stack spacing={1}>
                    {diffQuery.data.fixed_findings.map((finding, idx) => (
                      <Paper 
                        key={idx}
                        sx={{ 
                          p: 1.5, 
                          bgcolor: alpha(theme.palette.success.main, 0.05),
                          border: `1px solid ${alpha(theme.palette.success.main, 0.2)}`,
                          "&:hover": { bgcolor: alpha(theme.palette.success.main, 0.1) }
                        }}
                      >
                        <Stack direction="row" alignItems="center" spacing={1}>
                          <Chip 
                            size="small" 
                            label={finding.severity}
                            sx={{ 
                              bgcolor: alpha(theme.palette.success.main, 0.3),
                              fontSize: "0.65rem",
                              height: 20,
                              textDecoration: "line-through",
                            }}
                          />
                          <Typography variant="body2" sx={{ textDecoration: "line-through", opacity: 0.7 }}>
                            {finding.type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" fontFamily="monospace" sx={{ textDecoration: "line-through", opacity: 0.7 }}>
                            {finding.file_path}{finding.start_line ? `:${finding.start_line}` : ""}
                          </Typography>
                        </Stack>
                        {finding.summary && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block", textDecoration: "line-through", opacity: 0.7 }}>
                            {finding.summary}
                          </Typography>
                        )}
                      </Paper>
                    ))}
                  </Stack>
                </Box>
              )}

              {/* No Changes */}
              {diffQuery.data.new_findings.length === 0 && diffQuery.data.fixed_findings.length === 0 && (
                <Box sx={{ p: 4, textAlign: "center" }}>
                  <Typography variant="h6" color="success.main">🎉 No Changes</Typography>
                  <Typography color="text.secondary">
                    The scan results are identical between these two scans.
                  </Typography>
                </Box>
              )}
            </Box>
          ) : null}
        </Paper>
      )}

      {/* TODOs View (Feature: TODO/FIXME Scanner) */}
      {viewMode === "todos" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          {todosQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress size={40} />
              <Typography sx={{ ml: 2 }}>Scanning for TODOs...</Typography>
            </Box>
          ) : todosQuery.isError ? (
            <Alert severity="error">Failed to scan for TODOs</Alert>
          ) : todosQuery.data ? (
            <Box>
              {/* Summary Header */}
              <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 3 }} flexWrap="wrap">
                <Typography variant="h6">
                  📝 Code Comments Scanner
                </Typography>
                <Chip 
                  label={`${todosQuery.data.total} total`}
                  size="small"
                  sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}
                />
                {Object.entries(todosQuery.data.summary).map(([type, count]) => (
                  <Chip
                    key={type}
                    size="small"
                    label={`${type}: ${count}`}
                    sx={{
                      bgcolor: alpha(
                        type === "FIXME" || type === "BUG" ? theme.palette.error.main :
                        type === "TODO" ? theme.palette.warning.main :
                        type === "HACK" || type === "XXX" ? theme.palette.info.main :
                        theme.palette.success.main,
                        0.15
                      ),
                      color: type === "FIXME" || type === "BUG" ? theme.palette.error.main :
                        type === "TODO" ? theme.palette.warning.main :
                        type === "HACK" || type === "XXX" ? theme.palette.info.main :
                        theme.palette.success.main,
                    }}
                  />
                ))}
              </Stack>

              {todosQuery.data.total === 0 ? (
                <Box sx={{ p: 4, textAlign: "center" }}>
                  <Typography variant="h6" color="success.main">✨ Clean Code!</Typography>
                  <Typography color="text.secondary">
                    No TODO, FIXME, HACK, or BUG comments found in the codebase.
                  </Typography>
                </Box>
              ) : (
                <Box sx={{ maxHeight: 500, overflow: "auto" }}>
                  {Object.entries(todosQuery.data.by_file).map(([filePath, items]) => (
                    <Box key={filePath} sx={{ mb: 2 }}>
                      <Typography 
                        variant="subtitle2" 
                        fontFamily="monospace"
                        sx={{ 
                          bgcolor: alpha(theme.palette.background.default, 0.5),
                          p: 1,
                          borderRadius: 1,
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                        }}
                        onClick={() => {
                          setPreviewFile(filePath);
                          setViewMode("tree");
                        }}
                      >
                        📄 {filePath} ({items.length})
                      </Typography>
                      <Stack spacing={0.5} sx={{ pl: 2, mt: 1 }}>
                        {items.map((item, idx) => (
                          <Paper
                            key={idx}
                            sx={{
                              p: 1,
                              bgcolor: alpha(
                                item.type === "FIXME" || item.type === "BUG" ? theme.palette.error.main :
                                item.type === "TODO" ? theme.palette.warning.main :
                                item.type === "HACK" || item.type === "XXX" ? theme.palette.info.main :
                                theme.palette.success.main,
                                0.05
                              ),
                              border: `1px solid ${alpha(
                                item.type === "FIXME" || item.type === "BUG" ? theme.palette.error.main :
                                item.type === "TODO" ? theme.palette.warning.main :
                                item.type === "HACK" || item.type === "XXX" ? theme.palette.info.main :
                                theme.palette.success.main,
                                0.2
                              )}`,
                              cursor: "pointer",
                              "&:hover": { 
                                bgcolor: alpha(theme.palette.primary.main, 0.08),
                              },
                            }}
                            onClick={() => {
                              setPreviewFile(filePath);
                              setViewMode("tree");
                              setTimeout(() => handleJumpToFinding(item.line), 500);
                            }}
                          >
                            <Stack direction="row" alignItems="center" spacing={1}>
                              <Chip
                                size="small"
                                label={item.type}
                                sx={{
                                  height: 20,
                                  fontSize: "0.65rem",
                                  fontWeight: 700,
                                  bgcolor: alpha(
                                    item.type === "FIXME" || item.type === "BUG" ? theme.palette.error.main :
                                    item.type === "TODO" ? theme.palette.warning.main :
                                    item.type === "HACK" || item.type === "XXX" ? theme.palette.info.main :
                                    theme.palette.success.main,
                                    0.2
                                  ),
                                }}
                              />
                              <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                                L{item.line}
                              </Typography>
                              <Typography variant="body2" sx={{ flex: 1 }}>
                                {item.text || "(no description)"}
                              </Typography>
                            </Stack>
                          </Paper>
                        ))}
                      </Stack>
                    </Box>
                  ))}
                </Box>
              )}
            </Box>
          ) : null}
        </Paper>
      )}

      {/* Secrets View (Feature: Secrets/Credentials Scanner) */}
      {viewMode === "secrets" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          {secretsQuery.isLoading ? (
            <Box sx={{ display: "flex", justifyContent: "center", p: 4 }}>
              <CircularProgress size={40} />
              <Typography sx={{ ml: 2 }}>Scanning for secrets (AI validation enabled)...</Typography>
            </Box>
          ) : secretsQuery.isError ? (
            <Alert severity="error">Failed to scan for secrets</Alert>
          ) : secretsQuery.data ? (
            <Box>
              {/* Summary Header */}
              <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }} flexWrap="wrap">
                <Typography variant="h6">
                  🔐 Secrets & Credentials Scanner
                </Typography>
                <Chip 
                  label={`${secretsQuery.data.total} found`}
                  size="small"
                  sx={{ bgcolor: alpha(theme.palette.error.main, 0.1) }}
                />
                {secretsQuery.data.ai_validated && (
                  <Chip 
                    icon={<span style={{ fontSize: "0.8rem" }}>🤖</span>}
                    label={`AI Validated${secretsQuery.data.ai_filtered_count ? ` (${secretsQuery.data.ai_filtered_count} false positives filtered)` : ''}`}
                    size="small"
                    sx={{ 
                      bgcolor: alpha(theme.palette.success.main, 0.1),
                      color: theme.palette.success.main,
                    }}
                  />
                )}
                {secretsQuery.data.ai_error && (
                  <Chip 
                    label="AI validation failed"
                    size="small"
                    sx={{ 
                      bgcolor: alpha(theme.palette.warning.main, 0.1),
                      color: theme.palette.warning.main,
                    }}
                  />
                )}
              </Stack>
              
              {/* Type breakdown chips */}
              <Stack direction="row" spacing={1} sx={{ mb: 3 }} flexWrap="wrap" useFlexGap>
                {Object.entries(secretsQuery.data.summary).map(([type, count]) => {
                  // Categorize secret types for coloring
                  const isCritical = ["password", "private_key", "aws_secret", "connection_string", "url_with_creds", "db_password", "credit_card", "ssn"].includes(type);
                  const isHigh = ["api_key", "token", "aws_key", "github_token", "jwt", "stripe_key", "slack_webhook", "openai_key", "anthropic_key", "db_user"].includes(type);
                  const isPII = ["email", "phone", "phone_intl", "username", "user_id", "hardcoded_name", "address", "ip_address"].includes(type);
                  
                  return (
                    <Chip
                      key={type}
                      size="small"
                      label={`${type.replace(/_/g, " ")}: ${count}`}
                      sx={{
                        bgcolor: alpha(
                          isCritical ? theme.palette.error.main :
                          isHigh ? theme.palette.warning.main :
                          isPII ? theme.palette.info.main :
                          theme.palette.success.main,
                          0.15
                        ),
                        color: isCritical ? theme.palette.error.main :
                          isHigh ? theme.palette.warning.main :
                          isPII ? theme.palette.info.main :
                          theme.palette.success.main,
                      }}
                    />
                  );
                })}
              </Stack>

              {secretsQuery.data.total === 0 ? (
                <Box sx={{ p: 4, textAlign: "center" }}>
                  <Typography variant="h6" color="success.main">✨ No Secrets Found!</Typography>
                  <Typography color="text.secondary">
                    {secretsQuery.data.ai_validated 
                      ? "AI analysis confirmed no real hardcoded secrets or PII in the codebase."
                      : "No hardcoded secrets, API keys, passwords, credentials, or PII detected in the codebase."}
                  </Typography>
                </Box>
              ) : (
                <Box sx={{ maxHeight: 500, overflow: "auto" }}>
                  {Object.entries(secretsQuery.data.by_file).map(([filePath, items]) => (
                    <Box key={filePath} sx={{ mb: 2 }}>
                      <Typography 
                        variant="subtitle2" 
                        fontFamily="monospace"
                        sx={{ 
                          bgcolor: alpha(theme.palette.background.default, 0.5),
                          p: 1,
                          borderRadius: 1,
                          cursor: "pointer",
                          "&:hover": { bgcolor: alpha(theme.palette.error.main, 0.1) },
                        }}
                        onClick={() => {
                          setPreviewFile(filePath);
                          setViewMode("tree");
                        }}
                      >
                        📄 {filePath} ({items.length})
                      </Typography>
                      <Stack spacing={0.5} sx={{ pl: 2, mt: 1 }}>
                        {items.map((item: SecretItem, idx: number) => {
                          // Use AI risk level if available, otherwise fall back to regex severity
                          const effectiveSeverity = item.ai_risk_level || item.severity;
                          const severityColor = 
                            effectiveSeverity === "critical" ? theme.palette.error.main :
                            effectiveSeverity === "high" ? theme.palette.warning.main :
                            effectiveSeverity === "medium" ? theme.palette.info.main :
                            effectiveSeverity === "none" ? theme.palette.grey[500] :
                            theme.palette.text.secondary;
                          
                          return (
                            <Paper
                              key={idx}
                              sx={{
                                p: 1,
                                bgcolor: alpha(severityColor, 0.05),
                                border: `1px solid ${alpha(severityColor, 0.2)}`,
                                cursor: "pointer",
                                "&:hover": { 
                                  bgcolor: alpha(severityColor, 0.1),
                                },
                              }}
                              onClick={() => {
                                setPreviewFile(filePath);
                                setViewMode("tree");
                                setTimeout(() => handleJumpToFinding(item.line), 500);
                              }}
                            >
                              <Stack direction="row" alignItems="center" spacing={1} flexWrap="wrap">
                                <Chip
                                  size="small"
                                  label={item.type.replace(/_/g, " ")}
                                  sx={{
                                    height: 20,
                                    fontSize: "0.65rem",
                                    fontWeight: 700,
                                    bgcolor: alpha(severityColor, 0.2),
                                    color: severityColor,
                                  }}
                                />
                                <Chip
                                  size="small"
                                  label={effectiveSeverity}
                                  sx={{
                                    height: 18,
                                    fontSize: "0.6rem",
                                    fontWeight: 700,
                                    bgcolor: alpha(severityColor, 0.15),
                                    color: severityColor,
                                  }}
                                />
                                {item.ai_validated && item.ai_confidence !== undefined && (
                                  <Tooltip title={item.ai_reason || "AI validated"}>
                                    <Chip
                                      size="small"
                                      label={`🤖 ${Math.round(item.ai_confidence * 100)}%`}
                                      sx={{
                                        height: 18,
                                        fontSize: "0.6rem",
                                        fontWeight: 700,
                                        bgcolor: alpha(theme.palette.info.main, 0.1),
                                        color: theme.palette.info.main,
                                      }}
                                    />
                                  </Tooltip>
                                )}
                                <Typography variant="caption" color="text.secondary" fontFamily="monospace">
                                  L{item.line}
                                </Typography>
                                <Typography 
                                  variant="body2" 
                                  fontFamily="monospace" 
                                  sx={{ 
                                    flex: 1,
                                    bgcolor: alpha(theme.palette.error.main, 0.1),
                                    px: 1,
                                    py: 0.25,
                                    borderRadius: 0.5,
                                    fontSize: "0.75rem",
                                    minWidth: 100,
                                    border: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
                                    fontWeight: 600,
                                    wordBreak: "break-all",
                                  }}
                                  title={`Full value: ${item.value}`}
                                >
                                  🔓 {item.value}
                                </Typography>
                              </Stack>
                              {item.ai_reason && (
                                <Typography 
                                  variant="caption" 
                                  color="text.secondary" 
                                  sx={{ 
                                    display: "block", 
                                    mt: 0.5, 
                                    pl: 1,
                                    fontStyle: "italic",
                                  }}
                                >
                                  💡 {item.ai_reason}
                                </Typography>
                              )}
                            </Paper>
                          );
                        })}
                      </Stack>
                    </Box>
                  ))}
                </Box>
              )}
            </Box>
          ) : null}
        </Paper>
      )}

      {/* Architecture Diagram View */}
      {viewMode === "diagram" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 2,
                bgcolor: alpha(theme.palette.primary.main, 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "1.5rem",
              }}
            >
              🕸️
            </Box>
            <Box>
              <Typography variant="h6">Architecture Diagram</Typography>
              <Typography variant="body2" color="text.secondary">
                AI-generated visual representation of the codebase structure
              </Typography>
            </Box>
            {diagramQuery.data?.cached && (
              <Chip 
                size="small" 
                label="Cached" 
                sx={{ ml: "auto" }}
                color="success"
                variant="outlined"
              />
            )}
          </Stack>

          {diagramQuery.isLoading && (
            <Box sx={{ textAlign: "center", py: 6 }}>
              <CircularProgress size={48} />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                🤖 Generating architecture diagram with AI...
              </Typography>
              <Typography variant="caption" color="text.secondary">
                This may take a few seconds
              </Typography>
            </Box>
          )}

          {diagramQuery.isError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Failed to generate diagram. Make sure Gemini API is configured.
            </Alert>
          )}

          {diagramQuery.data && (
            <MermaidDiagram 
              code={diagramQuery.data.diagram}
              title="Codebase Architecture"
              maxHeight={600}
              showControls={true}
              showCodeToggle={true}
            />
          )}
        </Paper>
      )}

      {/* CVE/CWE Vulnerabilities View */}
      {viewMode === "cves" && (
        <Paper
          sx={{
            p: 2,
            bgcolor: alpha(theme.palette.background.paper, 0.5),
            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
            borderRadius: 2,
          }}
        >
          <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 2,
                bgcolor: alpha(theme.palette.error.main, 0.1),
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: "1.5rem",
              }}
            >
              🛡️
            </Box>
            <Box>
              <Typography variant="h6">CVE/CWE Vulnerabilities</Typography>
              <Typography variant="body2" color="text.secondary">
                Known vulnerabilities from dependency scanning and code analysis
              </Typography>
            </Box>
          </Stack>

          {cvesQuery.isLoading && (
            <Box sx={{ textAlign: "center", py: 6 }}>
              <CircularProgress size={48} />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                Loading vulnerability data...
              </Typography>
            </Box>
          )}

          {cvesQuery.isError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              Failed to load vulnerability data.
            </Alert>
          )}

          {cvesQuery.data && (
            <Stack spacing={3}>
              {/* Summary Cards */}
              <Grid container spacing={2}>
                <Grid item xs={6} sm={3}>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      textAlign: "center",
                      bgcolor: alpha(theme.palette.error.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" color="error.main" fontWeight={700}>
                      {cvesQuery.data.cves.critical_count}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">Critical CVEs</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      textAlign: "center",
                      bgcolor: alpha(theme.palette.warning.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.warning.main, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" color="warning.main" fontWeight={700}>
                      {cvesQuery.data.cves.high_count}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">High CVEs</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      textAlign: "center",
                      bgcolor: alpha(theme.palette.info.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" color="info.main" fontWeight={700}>
                      {cvesQuery.data.cwes.unique_cwes}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">CWE Types</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      textAlign: "center",
                      bgcolor: alpha(theme.palette.secondary.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.secondary.main, 0.2)}`,
                    }}
                  >
                    <Typography variant="h4" color="secondary.main" fontWeight={700}>
                      {cvesQuery.data.summary.total_findings}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">Total Findings</Typography>
                  </Paper>
                </Grid>
              </Grid>

              {/* CVE List */}
              {cvesQuery.data.cves.items.length > 0 && (
                <Box>
                  <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>
                    CVE Details ({cvesQuery.data.cves.total})
                  </Typography>
                  <TableContainer component={Paper} sx={{ bgcolor: "transparent" }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>CVE ID</TableCell>
                          <TableCell>Severity</TableCell>
                          <TableCell>CVSS</TableCell>
                          <TableCell>Affected Packages</TableCell>
                          <TableCell>EPSS</TableCell>
                          <TableCell>Fix</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {cvesQuery.data.cves.items.map((cve: CVEEntry) => (
                          <TableRow key={cve.cve_id} hover>
                            <TableCell>
                              <Tooltip title={cve.title || cve.cve_id}>
                                <Typography 
                                  component="a"
                                  href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  sx={{ 
                                    color: theme.palette.primary.main,
                                    textDecoration: "none",
                                    fontFamily: "monospace",
                                    fontSize: "0.875rem",
                                    "&:hover": { textDecoration: "underline" }
                                  }}
                                >
                                  {cve.cve_id}
                                </Typography>
                              </Tooltip>
                              {cve.cisa_kev && (
                                <Chip 
                                  label="KEV" 
                                  size="small" 
                                  color="error" 
                                  sx={{ ml: 1, height: 18, fontSize: "0.65rem" }}
                                />
                              )}
                            </TableCell>
                            <TableCell>
                              <Chip
                                label={cve.severity}
                                size="small"
                                sx={{
                                  bgcolor: 
                                    cve.severity === "critical" ? alpha(theme.palette.error.main, 0.2) :
                                    cve.severity === "high" ? alpha(theme.palette.warning.main, 0.2) :
                                    cve.severity === "medium" ? alpha(theme.palette.info.main, 0.2) :
                                    alpha(theme.palette.success.main, 0.2),
                                  color:
                                    cve.severity === "critical" ? theme.palette.error.main :
                                    cve.severity === "high" ? theme.palette.warning.main :
                                    cve.severity === "medium" ? theme.palette.info.main :
                                    theme.palette.success.main,
                                  fontWeight: 600,
                                  textTransform: "capitalize",
                                }}
                              />
                            </TableCell>
                            <TableCell>
                              <Typography 
                                variant="body2" 
                                fontWeight={600}
                                color={
                                  (cve.cvss_score || 0) >= 9.0 ? "error.main" :
                                  (cve.cvss_score || 0) >= 7.0 ? "warning.main" :
                                  (cve.cvss_score || 0) >= 4.0 ? "info.main" :
                                  "text.secondary"
                                }
                              >
                                {cve.cvss_score?.toFixed(1) || "N/A"}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Stack direction="row" spacing={0.5} flexWrap="wrap">
                                {cve.affected_packages.slice(0, 3).map((pkg) => (
                                  <Chip 
                                    key={pkg}
                                    label={pkg}
                                    size="small"
                                    variant="outlined"
                                    sx={{ fontSize: "0.7rem", height: 20 }}
                                  />
                                ))}
                                {cve.affected_packages.length > 3 && (
                                  <Chip 
                                    label={`+${cve.affected_packages.length - 3}`}
                                    size="small"
                                    sx={{ fontSize: "0.7rem", height: 20 }}
                                  />
                                )}
                              </Stack>
                            </TableCell>
                            <TableCell>
                              {cve.epss_score != null ? (
                                <Tooltip title={`${(cve.epss_score * 100).toFixed(1)}% probability of exploitation in next 30 days`}>
                                  <Typography 
                                    variant="body2"
                                    color={cve.epss_score > 0.1 ? "error.main" : "text.secondary"}
                                    fontWeight={cve.epss_score > 0.1 ? 600 : 400}
                                  >
                                    {(cve.epss_score * 100).toFixed(1)}%
                                  </Typography>
                                </Tooltip>
                              ) : (
                                <Typography variant="body2" color="text.secondary">-</Typography>
                              )}
                            </TableCell>
                            <TableCell>
                              {cve.fix_available ? (
                                <Chip label="Available" size="small" color="success" variant="outlined" sx={{ fontSize: "0.7rem" }} />
                              ) : (
                                <Typography variant="body2" color="text.secondary">-</Typography>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              )}

              {/* CWE List */}
              {cvesQuery.data.cwes.items.length > 0 && (
                <Box>
                  <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>
                    CWE Breakdown ({cvesQuery.data.cwes.items.length} weakness types)
                  </Typography>
                  <Grid container spacing={2}>
                    {cvesQuery.data.cwes.items.map((cwe: CWEEntry) => (
                      <Grid item xs={12} sm={6} md={4} key={cwe.cwe_id}>
                        <Paper
                          sx={{
                            p: 2,
                            bgcolor: alpha(theme.palette.background.paper, 0.5),
                            border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                            "&:hover": {
                              borderColor: theme.palette.primary.main,
                            },
                          }}
                        >
                          <Stack direction="row" justifyContent="space-between" alignItems="flex-start">
                            <Box>
                              <Typography 
                                component="a"
                                href={cwe.mitre_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                sx={{ 
                                  color: theme.palette.primary.main,
                                  textDecoration: "none",
                                  fontFamily: "monospace",
                                  fontSize: "0.875rem",
                                  fontWeight: 600,
                                  "&:hover": { textDecoration: "underline" }
                                }}
                              >
                                {cwe.cwe_id}
                              </Typography>
                              <Typography variant="body2" sx={{ mt: 0.5 }}>
                                {cwe.name}
                              </Typography>
                            </Box>
                            <Chip 
                              label={cwe.count} 
                              size="small"
                              color="primary"
                              sx={{ fontWeight: 600 }}
                            />
                          </Stack>
                          {cwe.severity_breakdown && Object.keys(cwe.severity_breakdown).length > 0 && (
                            <Stack direction="row" spacing={0.5} sx={{ mt: 1 }} flexWrap="wrap">
                              {Object.entries(cwe.severity_breakdown).map(([severity, count]) => (
                                <Chip
                                  key={severity}
                                  label={`${severity}: ${count}`}
                                  size="small"
                                  sx={{
                                    fontSize: "0.65rem",
                                    height: 18,
                                    bgcolor: 
                                      severity === "critical" ? alpha(theme.palette.error.main, 0.2) :
                                      severity === "high" ? alpha(theme.palette.warning.main, 0.2) :
                                      severity === "medium" ? alpha(theme.palette.info.main, 0.2) :
                                      alpha(theme.palette.success.main, 0.2),
                                    textTransform: "capitalize",
                                  }}
                                />
                              ))}
                            </Stack>
                          )}
                        </Paper>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              )}

              {/* Empty State */}
              {cvesQuery.data.cves.items.length === 0 && cvesQuery.data.cwes.items.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <Typography variant="h6" color="success.main" sx={{ mb: 1 }}>
                    🎉 No Known Vulnerabilities Found
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    No CVEs or CWEs were identified in the scanned dependencies or code.
                  </Typography>
                </Box>
              )}
            </Stack>
          )}
        </Paper>
      )}

      {/* File Metadata Dialog */}
      <FileMetadataDialog
        file={selectedFile}
        open={metadataOpen}
        onClose={() => {
          setMetadataOpen(false);
          setSelectedFile(null);
        }}
      />
    </Box>
  );
}

type SensitiveDataOccurrence = {
  file_path?: string;
  line_number?: number;
  line_excerpt?: string;
};

type SensitiveDataItem = {
  kind?: string;
  label?: string | null;
  masked_value?: string;
  value_hash?: string;
  confidence?: number;
  source?: string;
  occurrences?: SensitiveDataOccurrence[];
  gemini?: {
    type?: string;
    confidence?: number;
    likely_placeholder?: boolean;
    reason?: string;
  };
};

type SensitiveDataCategory = {
  label?: string;
  count?: number;
  items?: SensitiveDataItem[];
};

type SensitiveDataInventory = {
  totals?: Record<string, number>;
  categories?: Record<string, SensitiveDataCategory>;
  used_gemini?: boolean;
  gemini_model?: string | null;
  gemini_error?: string | null;
  truncated?: boolean;
  error?: string;
};

const SensitiveDataIcon = ({ color }: { color: string }) => (
  <svg width="28" height="28" viewBox="0 0 24 24" fill={color}>
    <path d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5zm-3 8V6a3 3 0 0 1 6 0v3H9zm3 4a2 2 0 0 0-1 3.732V18a1 1 0 0 0 2 0v-1.268A2 2 0 0 0 12 13z" />
  </svg>
);

function SensitiveDataInventoryPanel({ inventory }: { inventory: SensitiveDataInventory }) {
  const theme = useTheme();
  const [expanded, setExpanded] = useState(false);

  const totals = inventory?.totals || {};
  const categories = inventory?.categories || {};

  const categoryOrder: Array<{ key: string; fallbackLabel: string }> = [
    { key: "api_keys", fallbackLabel: "API Keys & Tokens" },
    { key: "passwords", fallbackLabel: "Passwords" },
    { key: "usernames", fallbackLabel: "Usernames" },
    { key: "emails", fallbackLabel: "Email Addresses" },
    { key: "phones", fallbackLabel: "Phone Numbers" },
    { key: "names", fallbackLabel: "People Names" },
  ];

  const hasAny =
    typeof totals.total === "number"
      ? totals.total > 0
      : Object.values(totals).some((v) => typeof v === "number" && v > 0);

  if (!hasAny && !inventory?.error) return null;

  const chipColor = (key: string) => {
    const palette: Record<string, string> = {
      api_keys: theme.palette.error.main,
      passwords: theme.palette.warning.main,
      usernames: theme.palette.info.main,
      emails: theme.palette.secondary.main,
      phones: theme.palette.success.main,
      names: theme.palette.primary.main,
    };
    return palette[key] || theme.palette.text.secondary;
  };

  return (
    <Card
      sx={{
        mb: 3,
        background: `linear-gradient(135deg, ${alpha(theme.palette.secondary.main, 0.06)} 0%, ${alpha(theme.palette.primary.main, 0.04)} 100%)`,
        border: `1px solid ${alpha(theme.palette.secondary.main, 0.18)}`,
        borderRadius: 3,
        overflow: "hidden",
      }}
    >
      <CardContent sx={{ p: 3 }}>
        <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
          <Box
            sx={{
              width: 48,
              height: 48,
              borderRadius: 2,
              bgcolor: alpha(theme.palette.secondary.main, 0.12),
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <SensitiveDataIcon color={theme.palette.secondary.main} />
          </Box>
          <Box sx={{ flexGrow: 1 }}>
            <Typography variant="h6" fontWeight={800}>
              Sensitive Data Inventory
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Extracted emails, phone numbers, usernames, passwords, and API keys (values masked by default)
            </Typography>
          </Box>
          <Button
            size="small"
            endIcon={<ExpandIcon expanded={expanded} />}
            onClick={() => setExpanded(!expanded)}
            sx={{ textTransform: "none" }}
          >
            {expanded ? "Hide" : "View"}
          </Button>
        </Stack>

        {inventory?.error && (
          <Alert severity="warning" sx={{ mt: 2 }}>
            Sensitive data inventory unavailable: {inventory.error}
          </Alert>
        )}

        {!inventory?.error && (
          <>
            <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mt: 1 }}>
              {categoryOrder
                .map(({ key }) => ({ key, count: totals[key] }))
                .filter((x) => typeof x.count === "number" && x.count > 0)
                .map(({ key, count }) => {
                  const c = chipColor(key);
                  return (
                    <Chip
                      key={key}
                      size="small"
                      label={`${count} ${key.replace("_", " ")}`}
                      sx={{
                        bgcolor: alpha(c, 0.12),
                        color: c,
                        border: `1px solid ${alpha(c, 0.25)}`,
                        fontWeight: 700,
                        fontSize: "0.7rem",
                      }}
                    />
                  );
                })}

              {inventory.truncated && (
                <Chip
                  size="small"
                  label="truncated"
                  sx={{
                    bgcolor: alpha(theme.palette.warning.main, 0.12),
                    color: theme.palette.warning.main,
                    border: `1px solid ${alpha(theme.palette.warning.main, 0.25)}`,
                    fontWeight: 700,
                    fontSize: "0.7rem",
                  }}
                />
              )}

              {inventory.used_gemini && (
                <Chip
                  size="small"
                  label={`AI-reviewed${inventory.gemini_model ? ` (${inventory.gemini_model})` : ""}`}
                  sx={{
                    bgcolor: alpha(theme.palette.info.main, 0.12),
                    color: theme.palette.info.main,
                    border: `1px solid ${alpha(theme.palette.info.main, 0.25)}`,
                    fontWeight: 700,
                    fontSize: "0.7rem",
                  }}
                />
              )}
            </Stack>

            {inventory.gemini_error && (
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                AI classification error: {inventory.gemini_error}
              </Typography>
            )}

            <Collapse in={expanded}>
              <Grid container spacing={2} sx={{ mt: 0.5 }}>
                {categoryOrder.map(({ key, fallbackLabel }) => {
                  const cat = categories[key];
                  const items = (cat?.items || []) as SensitiveDataItem[];
                  if (!items.length) return null;

                  return (
                    <Grid item xs={12} md={6} key={key}>
                      <Paper
                        sx={{
                          p: 2,
                          borderRadius: 2,
                          border: `1px solid ${alpha(theme.palette.divider, 0.12)}`,
                          bgcolor: alpha(theme.palette.background.paper, 0.7),
                        }}
                      >
                        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
                          <Typography variant="subtitle1" fontWeight={800}>
                            {cat?.label || fallbackLabel}
                          </Typography>
                          <Chip
                            size="small"
                            label={items.length}
                            sx={{
                              bgcolor: alpha(theme.palette.text.primary, 0.08),
                              fontWeight: 800,
                              height: 22,
                            }}
                          />
                        </Stack>

                        <Stack spacing={1}>
                          {items.slice(0, 50).map((item, idx) => {
                            const occs = item.occurrences || [];
                            const locations = occs
                              .slice(0, 5)
                              .map((o) => `${o.file_path || "?"}:${o.line_number || "?"}`)
                              .join("\n");

                            const isSecretLike = key === "api_keys" || key === "passwords";
                            const placeholder = item.gemini?.likely_placeholder;

                            return (
                              <Box
                                key={item.value_hash || `${key}-${idx}`}
                                sx={{
                                  p: 1.25,
                                  borderRadius: 1.5,
                                  border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
                                  bgcolor: alpha(theme.palette.background.default, 0.35),
                                }}
                              >
                                <Stack direction="row" alignItems="flex-start" justifyContent="space-between" spacing={1}>
                                  <Box sx={{ minWidth: 0 }}>
                                    <Typography
                                      variant="body2"
                                      sx={{
                                        fontFamily: isSecretLike ? "monospace" : "inherit",
                                        fontWeight: 700,
                                        wordBreak: "break-word",
                                      }}
                                    >
                                      {item.masked_value || "-"}
                                    </Typography>
                                    {(item.label || item.gemini?.reason) && (
                                      <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>
                                        {item.label ? `${item.label}` : ""}
                                        {item.label && item.gemini?.reason ? " • " : ""}
                                        {item.gemini?.reason ? item.gemini.reason : ""}
                                      </Typography>
                                    )}
                                  </Box>

                                  <Stack direction="row" spacing={0.75} alignItems="center">
                                    {placeholder && (
                                      <Chip
                                        size="small"
                                        label="example?"
                                        sx={{
                                          height: 20,
                                          fontSize: "0.65rem",
                                          bgcolor: alpha(theme.palette.warning.main, 0.12),
                                          color: theme.palette.warning.main,
                                          border: `1px solid ${alpha(theme.palette.warning.main, 0.25)}`,
                                          fontWeight: 700,
                                        }}
                                      />
                                    )}

                                    {item.gemini && (
                                      <Tooltip
                                        title={`Gemini: ${item.gemini.type || "unknown"} (${Math.round(
                                          (item.gemini.confidence || 0) * 100
                                        )}%)`}
                                      >
                                        <Chip
                                          size="small"
                                          label="AI"
                                          sx={{
                                            height: 20,
                                            fontSize: "0.65rem",
                                            bgcolor: alpha(theme.palette.info.main, 0.12),
                                            color: theme.palette.info.main,
                                            border: `1px solid ${alpha(theme.palette.info.main, 0.25)}`,
                                            fontWeight: 700,
                                            cursor: "help",
                                          }}
                                        />
                                      </Tooltip>
                                    )}

                                    <Tooltip title={locations || "No locations recorded"}>
                                      <Chip
                                        size="small"
                                        label={`${occs.length} loc`}
                                        sx={{
                                          height: 20,
                                          fontSize: "0.65rem",
                                          bgcolor: alpha(theme.palette.text.primary, 0.08),
                                          fontWeight: 800,
                                          cursor: "help",
                                        }}
                                      />
                                    </Tooltip>
                                  </Stack>
                                </Stack>
                              </Box>
                            );
                          })}
                        </Stack>

                        {items.length > 50 && (
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                            Showing first 50 items.
                          </Typography>
                        )}
                      </Paper>
                    </Grid>
                  );
                })}
              </Grid>
            </Collapse>
          </>
        )}
      </CardContent>
    </Card>
  );
}

// Sorting types
type SortField = "severity" | "type" | "file_path" | "start_line";
type SortOrder = "asc" | "desc";

export default function ReportDetailPage() {
  const { reportId } = useParams();
  const id = Number(reportId);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [pollExploit, setPollExploit] = useState(false);
  const [sortField, setSortField] = useState<SortField>("severity");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");
  const [exploitMode, setExploitMode] = useState<"auto" | "summary" | "full">("summary");

  // Chat state
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState<string | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);

  const reportQuery = useQuery({
    queryKey: ["report", id],
    queryFn: () => api.getReport(id),
    enabled: !!id,
  });

  // Query to get all reports for the same project (for diff feature)
  const projectReportsQuery = useQuery({
    queryKey: ["project-reports", reportQuery.data?.project_id],
    queryFn: () => api.getReports(reportQuery.data!.project_id),
    enabled: !!reportQuery.data?.project_id,
  });

  const findingsQuery = useQuery({
    queryKey: ["findings", id],
    queryFn: () => api.getFindings(id),
    enabled: !!id,
  });

  const exploitQuery = useQuery({
    queryKey: ["exploitability", id],
    queryFn: () => api.getExploitability(id),
    enabled: !!id,
    refetchInterval: pollExploit ? 3000 : false,
  });

  // Attack chain diagram for exploitability visualization
  const attackChainDiagramQuery = useQuery({
    queryKey: ["attack-chain-diagram", id],
    queryFn: () => api.getAttackChainDiagram(id, true),
    enabled: !!id && (exploitQuery.data?.length ?? 0) > 0,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  const aiInsightsQuery = useQuery({
    queryKey: ["ai-insights", id],
    queryFn: () => api.getAIInsights(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  const summaryQuery = useQuery({
    queryKey: ["codebase-summary", id],
    queryFn: () => api.getCodebaseSummary(id),
    enabled: !!id,
    staleTime: 5 * 60 * 1000, // Cache for 5 minutes
  });

  const startExploitMutation = useMutation({
    mutationFn: () => api.startExploitability(id, exploitMode),
    onSuccess: () => {
      setPollExploit(true);
      queryClient.invalidateQueries({ queryKey: ["exploitability", id] });
    },
  });

  useEffect(() => {
    if (pollExploit && (exploitQuery.data?.length ?? 0) > 0) {
      setPollExploit(false);
    }
  }, [pollExploit, exploitQuery.data]);

  const severityCounts = useMemo(() => {
    const counts = reportQuery.data?.data?.severity_counts as Record<string, number> | undefined;
    return counts || {};
  }, [reportQuery.data]);

  // Sort findings - AI-judged false positives go to the bottom automatically
  const sortedFindings = useMemo(() => {
    if (!findingsQuery.data) return [];
    
    return [...findingsQuery.data].sort((a, b) => {
      // Get AI analysis for both findings
      const aiA = a.details?.ai_analysis as { is_false_positive?: boolean; false_positive_score?: number; filtered_out?: boolean } | undefined;
      const aiB = b.details?.ai_analysis as { is_false_positive?: boolean; false_positive_score?: number; filtered_out?: boolean } | undefined;
      
      // First priority: filtered/false positive findings go to the bottom
      const aIsLowConfidence = aiA?.filtered_out || aiA?.is_false_positive || (aiA?.false_positive_score && aiA.false_positive_score > 0.5);
      const bIsLowConfidence = aiB?.filtered_out || aiB?.is_false_positive || (aiB?.false_positive_score && aiB.false_positive_score > 0.5);
      
      if (aIsLowConfidence && !bIsLowConfidence) return 1; // a goes to bottom
      if (!aIsLowConfidence && bIsLowConfidence) return -1; // b goes to bottom
      
      // If both are low confidence, sort by FP score (higher = more likely false positive = further down)
      if (aIsLowConfidence && bIsLowConfidence) {
        const fpScoreA = aiA?.false_positive_score || 0;
        const fpScoreB = aiB?.false_positive_score || 0;
        if (fpScoreA !== fpScoreB) return fpScoreB - fpScoreA; // Higher FP score goes further down
      }
      
      // Then apply normal sorting
      let comparison = 0;
      
      switch (sortField) {
        case "severity":
          const orderA = getSeverityConfig(a.severity, theme).order;
          const orderB = getSeverityConfig(b.severity, theme).order;
          comparison = orderA - orderB;
          break;
        case "type":
          comparison = (a.type || "").localeCompare(b.type || "");
          break;
        case "file_path":
          comparison = (a.file_path || "").localeCompare(b.file_path || "");
          break;
        case "start_line":
          comparison = (a.start_line || 0) - (b.start_line || 0);
          break;
      }
      
      return sortOrder === "asc" ? comparison : -comparison;
    });
  }, [findingsQuery.data, sortField, sortOrder, theme]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [chatMessages]);

  // Handle sending chat message
  const handleSendMessage = async () => {
    if (!chatInput.trim() || chatLoading || !id) return;

    const userMessage: ChatMessage = { role: "user", content: chatInput.trim() };
    setChatMessages((prev) => [...prev, userMessage]);
    setChatInput("");
    setChatLoading(true);
    setChatError(null);

    try {
      const response = await api.chatAboutReport(
        id,
        userMessage.content,
        chatMessages,
        activeTab === 2 ? "exploitability" : "findings"
      );

      if (response.error) {
        setChatError(response.error);
      } else {
        const assistantMessage: ChatMessage = { role: "assistant", content: response.response };
        setChatMessages((prev) => [...prev, assistantMessage]);
      }
    } catch (err: any) {
      setChatError(err.message || "Failed to send message");
    } finally {
      setChatLoading(false);
    }
  };

  // Handle Enter key in chat input
  const handleChatKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  async function handleExport(format: "markdown" | "pdf" | "docx") {
    const resp = await api.exportReport(id, format);
    const blob = await resp.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${id}.${format === "docx" ? "docx" : format === "pdf" ? "pdf" : "md"}`;
    a.click();
    window.URL.revokeObjectURL(url);
  }

  if (!id) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        Invalid report ID
      </Alert>
    );
  }

  return (
    <Box>
      {/* Back Navigation */}
      <Button
        startIcon={<BackIcon />}
        onClick={() => navigate(-1)}
        sx={{ mb: 3, color: "text.secondary" }}
      >
        Back
      </Button>

      {/* Loading State */}
      {reportQuery.isLoading && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Skeleton variant="text" width="40%" height={40} />
            <Skeleton variant="text" width="80%" />
            <Skeleton variant="text" width="60%" />
          </CardContent>
        </Card>
      )}

      {/* Error State */}
      {reportQuery.isError && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {(reportQuery.error as Error).message}
        </Alert>
      )}

      {/* Report Header */}
      {reportQuery.data && (
        <Card
          sx={{
            mb: 4,
            background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
          }}
        >
          <CardContent sx={{ p: 3 }}>
            <Grid container spacing={3} alignItems="center">
              <Grid item xs={12} md={8}>
                <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      color: "primary.main",
                    }}
                  >
                    <SecurityIcon />
                  </Box>
                  <Box>
                    <Typography variant="h4" fontWeight={700}>
                      {reportQuery.data.title || "Security Report"}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Generated on {new Date(reportQuery.data.created_at).toLocaleString()}
                    </Typography>
                  </Box>
                </Stack>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                  {reportQuery.data.summary || "No summary available"}
                </Typography>

                {/* Export Buttons */}
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => handleExport("markdown")}
                  >
                    Markdown
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => handleExport("pdf")}
                  >
                    PDF
                  </Button>
                  <Button
                    variant="outlined"
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => handleExport("docx")}
                  >
                    Word
                  </Button>
                </Stack>
              </Grid>

              <Grid item xs={12} md={4}>
                <Box sx={{ textAlign: "center" }}>
                  <Typography variant="caption" color="text.secondary" sx={{ mb: 1, display: "block" }}>
                    RISK SCORE
                  </Typography>
                  <RiskScoreDisplay score={reportQuery.data.overall_risk_score} />
                </Box>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {/* Severity Summary Cards */}
      {Object.keys(severityCounts).length > 0 && (
        <Grid container spacing={2} sx={{ mb: 4 }}>
          {["critical", "high", "medium", "low"].map((severity) => {
            const count = severityCounts[severity] || 0;
            const config = getSeverityConfig(severity, theme);
            return (
              <Grid item xs={6} sm={3} key={severity}>
                <Card
                  sx={{
                    bgcolor: config.bg,
                    border: `1px solid ${alpha(config.color, 0.3)}`,
                    cursor: "pointer",
                    transition: "all 0.2s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                      boxShadow: `0 4px 20px ${alpha(config.color, 0.3)}`,
                    },
                  }}
                  onClick={() => {
                    setSortField("severity");
                    setSortOrder("asc");
                  }}
                >
                  <CardContent sx={{ textAlign: "center", py: 2 }}>
                    <Typography
                      variant="h3"
                      fontWeight={700}
                      sx={{ color: config.color }}
                    >
                      {count}
                    </Typography>
                    <Typography
                      variant="caption"
                      fontWeight={600}
                      sx={{ color: config.color, letterSpacing: 1 }}
                    >
                      {config.label}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            );
          })}
        </Grid>
      )}

      {/* Tab Navigation */}
      <Box sx={{ mb: 3 }}>
        <Paper
          sx={{
            background: `linear-gradient(135deg, ${alpha(theme.palette.background.paper, 0.95)} 0%, ${alpha(theme.palette.background.paper, 0.85)} 100%)`,
            backdropFilter: "blur(20px)",
            border: `1px solid ${alpha(theme.palette.divider, 0.15)}`,
            borderRadius: 3,
            boxShadow: `0 4px 20px ${alpha(theme.palette.common.black, 0.1)}`,
          }}
        >
          <Tabs
            value={activeTab}
            onChange={(_, newValue) => setActiveTab(newValue)}
            centered
            sx={{
              minHeight: 80,
              "& .MuiTabs-indicator": {
                height: 4,
                borderRadius: "4px 4px 0 0",
                background: `linear-gradient(90deg, ${theme.palette.primary.main}, ${theme.palette.secondary.main})`,
              },
              "& .MuiTabs-flexContainer": {
                gap: 2,
              },
              "& .MuiTab-root": {
                textTransform: "none",
                fontWeight: 700,
                fontSize: "1.25rem",
                minHeight: 80,
                px: 5,
                py: 2,
                borderRadius: "12px 12px 0 0",
                transition: "all 0.3s ease",
                color: alpha(theme.palette.text.primary, 0.6),
                "&:hover": {
                  bgcolor: alpha(theme.palette.primary.main, 0.08),
                  color: theme.palette.text.primary,
                },
                "&.Mui-selected": {
                  color: theme.palette.primary.main,
                  bgcolor: alpha(theme.palette.primary.main, 0.1),
                },
                "& .MuiTab-iconWrapper": {
                  fontSize: "1.5rem",
                  marginRight: 1.5,
                },
              },
            }}
          >
            <Tab
              icon={<Box sx={{ display: "flex", transform: "scale(1.4)" }}><BugIcon /></Box>}
              iconPosition="start"
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>Findings</span>
                  <Chip 
                    size="small" 
                    label={findingsQuery.data?.length || 0}
                    sx={{ 
                      fontWeight: 700, 
                      fontSize: "0.85rem",
                      height: 26,
                      bgcolor: findingsQuery.data?.length ? alpha(theme.palette.error.main, 0.15) : alpha(theme.palette.success.main, 0.15),
                      color: findingsQuery.data?.length ? theme.palette.error.main : theme.palette.success.main,
                    }} 
                  />
                </Box>
              }
            />
            <Tab
              icon={<Box sx={{ display: "flex", transform: "scale(1.4)" }}><MapIcon /></Box>}
              iconPosition="start"
              label="Codebase Map"
            />
            <Tab
              icon={<Box sx={{ display: "flex", transform: "scale(1.4)" }}><AnalysisIcon /></Box>}
              iconPosition="start"
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>Exploitability</span>
                  {exploitQuery.data?.length ? (
                    <Chip 
                      size="small" 
                      label={exploitQuery.data.length}
                      sx={{ 
                        fontWeight: 700, 
                        fontSize: "0.85rem",
                        height: 26,
                        bgcolor: alpha(theme.palette.warning.main, 0.15),
                        color: theme.palette.warning.main,
                      }} 
                    />
                  ) : null}
                </Box>
              }
            />
          </Tabs>
        </Paper>
      </Box>

      {/* Tab Panel: Findings */}
      {activeTab === 0 && (
        <Box sx={{ mb: 4 }}>
          {/* AI Analysis Section */}
          <Stack spacing={3} sx={{ mb: 4 }}>
            {/* What Does This App Do - App Summary */}
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.05)} 0%, ${alpha(theme.palette.info.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.primary.main, 0.15)}`,
                borderRadius: 3,
                overflow: "hidden",
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill={theme.palette.primary.main}>
                      <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 17h-2v-2h2v2zm2.07-7.75l-.9.92C13.45 12.9 13 13.5 13 15h-2v-.5c0-1.1.45-2.1 1.17-2.83l1.24-1.26c.37-.36.59-.86.59-1.41 0-1.1-.9-2-2-2s-2 .9-2 2H8c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .88-.36 1.68-.93 2.25z"/>
                    </svg>
                  </Box>
                  <Box>
                    <Typography variant="h6" fontWeight={700} color="primary.main">
                      What Does This App Do?
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      AI-powered analysis of the codebase structure and purpose
                    </Typography>
                  </Box>
                </Box>
                
                {summaryQuery.isLoading && (
                  <Box>
                    <Skeleton variant="text" width="90%" height={24} />
                    <Skeleton variant="text" width="85%" height={24} />
                    <Skeleton variant="text" width="80%" height={24} />
                    <Skeleton variant="rectangular" height={100} sx={{ mt: 2, borderRadius: 2 }} />
                  </Box>
                )}
                
                {summaryQuery.data?.has_app_summary && summaryQuery.data.app_summary && (
                  <Box
                    sx={{
                      lineHeight: 1.7,
                      color: "text.secondary",
                      fontSize: "0.875rem",
                      "& .section-header": {
                        color: "text.primary",
                        fontWeight: 700,
                        fontSize: "0.95rem",
                        mt: 2.5,
                        mb: 1,
                        display: "block",
                        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
                        pb: 0.5,
                      },
                      "& .section-header:first-of-type": {
                        mt: 0,
                      },
                      "& strong": {
                        color: "text.primary",
                        fontWeight: 600,
                      },
                      "& ul, & ol": {
                        m: 0,
                        pl: 2.5,
                        "& li": {
                          mb: 0.5,
                        },
                      },
                      "& p": {
                        m: 0,
                        mb: 1,
                      },
                    }}
                    dangerouslySetInnerHTML={{
                      __html: (() => {
                        let html = summaryQuery.data.app_summary
                          .replace(/^#+\s*/gm, "")
                          .trim();
                        
                        // Convert section headers (bold text on its own line)
                        html = html.replace(/^\*\*([^*]+)\*\*$/gm, '<span class="section-header">$1</span>');
                        
                        // Convert remaining inline bold
                        html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
                        
                        // Convert bullet points to proper list
                        html = html.replace(/((?:^[•\-\*]\s+.+$\n?)+)/gm, (match) => {
                          const items = match.trim().split("\n")
                            .map(line => line.replace(/^[•\-\*]\s+/, "").trim())
                            .filter(Boolean)
                            .map(item => `<li>${item}</li>`)
                            .join("");
                          return `<ul>${items}</ul>`;
                        });
                        
                        // Convert numbered lists
                        html = html.replace(/((?:^\d+\.\s+.+$\n?)+)/gm, (match) => {
                          const items = match.trim().split("\n")
                            .map(line => line.replace(/^\d+\.\s+/, "").trim())
                            .filter(Boolean)
                            .map(item => `<li>${item}</li>`)
                            .join("");
                          return `<ol>${items}</ol>`;
                        });
                        
                        // Wrap remaining paragraphs
                        html = html.replace(/\n\n+/g, "</p><p>");
                        if (!html.startsWith("<")) html = "<p>" + html;
                        if (!html.endsWith(">")) html = html + "</p>";
                        
                        // Clean up empty paragraphs
                        html = html.replace(/<p>\s*<\/p>/g, "");
                        html = html.replace(/<p>\s*(<(?:ul|ol|span))/g, "$1");
                        html = html.replace(/(<\/(?:ul|ol|span)>)\s*<\/p>/g, "$1");
                        
                        return html;
                      })()
                    }}
                  />
                )}
                
                {!summaryQuery.isLoading && !summaryQuery.data?.has_app_summary && (
                  <Box sx={{ textAlign: "center", py: 3 }}>
                    <Typography color="text.secondary" sx={{ mb: 1 }}>
                      AI analysis not available
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Configure Gemini API key to enable AI-powered summaries
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>

            {/* App Security Report */}
            <Card
              sx={{
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.05)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.15)}`,
                borderRadius: 3,
                overflow: "hidden",
              }}
            >
              <CardContent sx={{ p: 3 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
                  <Box
                    sx={{
                      width: 48,
                      height: 48,
                      borderRadius: 2,
                      bgcolor: alpha(theme.palette.error.main, 0.1),
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                    }}
                  >
                    <svg width="28" height="28" viewBox="0 0 24 24" fill={theme.palette.error.main}>
                      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/>
                    </svg>
                  </Box>
                  <Box>
                    <Typography variant="h6" fontWeight={700} color="error.main">
                      App Security Report
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      Attack vectors, exploitation strategies, and potential impact
                    </Typography>
                  </Box>
                  {summaryQuery.data?.statistics && (
                    <Box sx={{ ml: "auto", display: "flex", gap: 1 }}>
                      {summaryQuery.data.statistics.findings_by_severity.critical > 0 && (
                        <Chip
                          size="small"
                          label={`${summaryQuery.data.statistics.findings_by_severity.critical} Critical`}
                          sx={{ bgcolor: alpha(theme.palette.error.main, 0.15), color: theme.palette.error.main, fontWeight: 600 }}
                        />
                      )}
                      {summaryQuery.data.statistics.findings_by_severity.high > 0 && (
                        <Chip
                          size="small"
                          label={`${summaryQuery.data.statistics.findings_by_severity.high} High`}
                          sx={{ bgcolor: alpha("#f97316", 0.15), color: "#f97316", fontWeight: 600 }}
                        />
                      )}
                    </Box>
                  )}
                </Box>
                
                {summaryQuery.isLoading && (
                  <Box>
                    <Skeleton variant="text" width="90%" height={24} />
                    <Skeleton variant="text" width="85%" height={24} />
                    <Skeleton variant="rectangular" height={150} sx={{ mt: 2, borderRadius: 2 }} />
                  </Box>
                )}
                
                {summaryQuery.data?.has_security_summary && summaryQuery.data.security_summary && (
                  <Box
                    sx={{
                      lineHeight: 1.7,
                      color: "text.secondary",
                      fontSize: "0.875rem",
                      "& .section-header": {
                        color: "error.main",
                        fontWeight: 700,
                        fontSize: "0.95rem",
                        mt: 2.5,
                        mb: 1,
                        display: "block",
                        borderBottom: `1px solid ${alpha(theme.palette.error.main, 0.3)}`,
                        pb: 0.5,
                      },
                      "& .section-header:first-of-type": {
                        mt: 0,
                      },
                      "& .risk-label": {
                        display: "inline-block",
                        px: 1,
                        py: 0.25,
                        borderRadius: 1,
                        fontWeight: 700,
                        fontSize: "0.8rem",
                        bgcolor: alpha(theme.palette.error.main, 0.15),
                        color: theme.palette.error.main,
                      },
                      "& strong": {
                        color: "text.primary",
                        fontWeight: 600,
                      },
                      "& ul, & ol": {
                        m: 0,
                        pl: 2.5,
                        "& li": {
                          mb: 0.75,
                        },
                      },
                      "& ol": {
                        "& li": {
                          pl: 0.5,
                        },
                      },
                      "& p": {
                        m: 0,
                        mb: 1,
                      },
                    }}
                    dangerouslySetInnerHTML={{
                      __html: (() => {
                        let html = summaryQuery.data.security_summary
                          .replace(/^#+\s*/gm, "")
                          .trim();
                        
                        // Convert section headers (bold text on its own line)
                        html = html.replace(/^\*\*([^*]+)\*\*$/gm, '<span class="section-header">$1</span>');
                        
                        // Highlight risk level labels
                        html = html.replace(/RISK LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)/gi, 
                          '<span class="risk-label">$1 RISK</span>');
                        
                        // Convert remaining inline bold
                        html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
                        
                        // Convert bullet points to proper list
                        html = html.replace(/((?:^[•\-\*]\s+.+$\n?)+)/gm, (match) => {
                          const items = match.trim().split("\n")
                            .map(line => line.replace(/^[•\-\*]\s+/, "").trim())
                            .filter(Boolean)
                            .map(item => `<li>${item}</li>`)
                            .join("");
                          return `<ul>${items}</ul>`;
                        });
                        
                        // Convert numbered lists
                        html = html.replace(/((?:^\d+\.\s+.+$\n?)+)/gm, (match) => {
                          const items = match.trim().split("\n")
                            .map(line => line.replace(/^\d+\.\s+/, "").trim())
                            .filter(Boolean)
                            .map(item => `<li>${item}</li>`)
                            .join("");
                          return `<ol>${items}</ol>`;
                        });
                        
                        // Wrap remaining paragraphs
                        html = html.replace(/\n\n+/g, "</p><p>");
                        if (!html.startsWith("<")) html = "<p>" + html;
                        if (!html.endsWith(">")) html = html + "</p>";
                        
                        // Clean up empty paragraphs
                        html = html.replace(/<p>\s*<\/p>/g, "");
                        html = html.replace(/<p>\s*(<(?:ul|ol|span))/g, "$1");
                        html = html.replace(/(<\/(?:ul|ol|span)>)\s*<\/p>/g, "$1");
                        
                        return html;
                      })()
                    }}
                  />
                )}
                
                {!summaryQuery.isLoading && !summaryQuery.data?.has_security_summary && findingsQuery.data && findingsQuery.data.length > 0 && (
                  <Box sx={{ textAlign: "center", py: 3 }}>
                    <Typography color="text.secondary" sx={{ mb: 1 }}>
                      Security analysis not available
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      Configure Gemini API key to enable AI-powered security insights
                    </Typography>
                  </Box>
                )}
                
                {!summaryQuery.isLoading && findingsQuery.data && findingsQuery.data.length === 0 && (
                  <Box sx={{ textAlign: "center", py: 3 }}>
                    <Typography color="success.main" fontWeight={500}>
                      ✅ No security issues detected in this scan
                    </Typography>
                  </Box>
                )}
              </CardContent>
            </Card>
          </Stack>

          {reportQuery.data?.data?.scan_stats?.sensitive_data_inventory && (
            <SensitiveDataInventoryPanel
              inventory={reportQuery.data.data.scan_stats.sensitive_data_inventory as SensitiveDataInventory}
            />
          )}

          {findingsQuery.isLoading && (
            <Paper sx={{ p: 3 }}>
              <Skeleton variant="rectangular" height={200} />
            </Paper>
          )}

          {findingsQuery.isError && (
            <Alert severity="error">{(findingsQuery.error as Error).message}</Alert>
          )}

          {findingsQuery.data && findingsQuery.data.length === 0 && (
            <Paper
              sx={{
                p: 4,
                textAlign: "center",
                bgcolor: alpha(theme.palette.success.main, 0.05),
                border: `1px dashed ${alpha(theme.palette.success.main, 0.3)}`,
              }}
            >
              <Typography color="success.main" fontWeight={500}>
                🎉 No vulnerabilities found!
              </Typography>
            </Paper>
          )}

          {sortedFindings.length > 0 && (
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
                    <TableCell sx={{ fontWeight: 700, width: 120 }}>
                      <TableSortLabel
                        active={sortField === "severity"}
                        direction={sortField === "severity" ? sortOrder : "asc"}
                        onClick={() => handleSort("severity")}
                      >
                        Severity
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>
                      <TableSortLabel
                        active={sortField === "type"}
                        direction={sortField === "type" ? sortOrder : "asc"}
                        onClick={() => handleSort("type")}
                      >
                        Type
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>
                      <TableSortLabel
                        active={sortField === "file_path"}
                        direction={sortField === "file_path" ? sortOrder : "asc"}
                        onClick={() => handleSort("file_path")}
                      >
                        File
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 80 }}>
                      <TableSortLabel
                        active={sortField === "start_line"}
                        direction={sortField === "start_line" ? sortOrder : "asc"}
                        onClick={() => handleSort("start_line")}
                      >
                        Line
                      </TableSortLabel>
                    </TableCell>
                    <TableCell sx={{ fontWeight: 700 }}>Summary</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 100 }}>AI Insights</TableCell>
                    <TableCell sx={{ fontWeight: 700, width: 60 }}>Notes</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedFindings.map((finding, idx) => {
                    const config = getSeverityConfig(finding.severity, theme);
                    // AI analysis data from details
                    const aiAnalysis = finding.details?.ai_analysis as {
                      is_false_positive?: boolean;
                      false_positive_score?: number;
                      false_positive_reason?: string;
                      severity_adjusted?: boolean;
                      original_severity?: string;
                      severity_reason?: string;
                      duplicate_group?: string;
                      attack_chain?: string;
                      data_flow_summary?: string;
                      filtered_out?: boolean;
                    } | undefined;
                    
                    // Check if this is an agentic finding
                    const isAgenticFinding = finding.type.startsWith("agentic-") || finding.details?.source === "agentic_ai";
                    
                    return (
                      <TableRow
                        key={finding.id}
                        sx={{
                          animation: `${fadeIn} 0.3s ease ${idx * 0.03}s both`,
                          "&:hover": {
                            bgcolor: alpha(theme.palette.primary.main, 0.03),
                          },
                          // Dim false positives, more for filtered out
                          opacity: aiAnalysis?.filtered_out ? 0.4 : (aiAnalysis?.is_false_positive ? 0.6 : 1),
                          // Strike-through for filtered findings
                          ...(aiAnalysis?.filtered_out && {
                            textDecoration: "line-through",
                            textDecorationColor: alpha(theme.palette.error.main, 0.5),
                          }),
                        }}
                      >
                        <TableCell>
                          <Chip
                            label={config.label}
                            size="small"
                            sx={{
                              bgcolor: config.bg,
                              color: config.color,
                              fontWeight: 600,
                              minWidth: 80,
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Chip
                            icon={finding.type.startsWith("agentic-") ? (
                              <span style={{ fontSize: "0.85rem", marginLeft: 4 }}>🤖</span>
                            ) : undefined}
                            label={finding.type.startsWith("agentic-") ? finding.type.replace("agentic-", "") : finding.type}
                            size="small"
                            variant={finding.type.startsWith("agentic-") ? "filled" : "outlined"}
                            sx={{ 
                              fontWeight: 500,
                              ...(finding.type.startsWith("agentic-") && {
                                bgcolor: alpha("#8b5cf6", 0.15),
                                color: "#8b5cf6",
                                border: `1px solid ${alpha("#8b5cf6", 0.3)}`,
                              })
                            }}
                          />
                        </TableCell>
                        <TableCell>
                          <Typography
                            variant="body2"
                            sx={{
                              fontFamily: "monospace",
                              fontSize: "0.75rem",
                              maxWidth: 300,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {finding.file_path?.split("/").pop() || "—"}
                          </Typography>
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{
                              display: "block",
                              maxWidth: 300,
                              overflow: "hidden",
                              textOverflow: "ellipsis",
                            }}
                          >
                            {finding.file_path}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                            {finding.start_line || "—"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="body2" sx={{ mb: 1 }}>
                              {finding.summary}
                            </Typography>
                            <CodeSnippetView reportId={id} finding={finding} />
                          </Box>
                        </TableCell>
                        <TableCell>
                          {aiAnalysis && (
                            <Stack direction="row" spacing={0.5} flexWrap="wrap">
                              {/* Low confidence findings just show a subtle tooltip - no chips needed since they're greyed out */}
                              {(aiAnalysis.filtered_out || aiAnalysis.is_false_positive) && (
                                <Tooltip title={aiAnalysis.false_positive_reason || 'Lower confidence finding'}>
                                  <Typography variant="caption" color="text.disabled" sx={{ cursor: "help", fontStyle: "italic" }}>
                                    {aiAnalysis.filtered_out ? "Low confidence" : "Possibly benign"}
                                  </Typography>
                                </Tooltip>
                              )}
                              {aiAnalysis.severity_adjusted && (
                                <Tooltip title={`Severity adjusted from ${aiAnalysis.original_severity}: ${aiAnalysis.severity_reason || 'Based on context'}`}>
                                  <Chip
                                    size="small"
                                    label={`↕ ${aiAnalysis.original_severity}`}
                                    sx={{
                                      bgcolor: alpha(theme.palette.info.main, 0.15),
                                      color: theme.palette.info.main,
                                      fontSize: "0.65rem",
                                      height: 20,
                                      cursor: "help",
                                    }}
                                  />
                                </Tooltip>
                              )}
                              {aiAnalysis.duplicate_group && (
                                <Tooltip title={`Related to findings in: ${aiAnalysis.duplicate_group}`}>
                                  <Chip
                                    size="small"
                                    label="🔗"
                                    sx={{
                                      bgcolor: alpha(theme.palette.secondary.main, 0.15),
                                      color: theme.palette.secondary.main,
                                      fontSize: "0.65rem",
                                      height: 20,
                                      cursor: "help",
                                    }}
                                  />
                                </Tooltip>
                              )}
                              {aiAnalysis.attack_chain && (
                                <Tooltip title={`Part of attack chain: ${aiAnalysis.attack_chain}`}>
                                  <Chip
                                    size="small"
                                    label="⛓️"
                                    sx={{
                                      bgcolor: alpha(theme.palette.error.main, 0.15),
                                      color: theme.palette.error.main,
                                      fontSize: "0.65rem",
                                      height: 20,
                                      cursor: "help",
                                    }}
                                  />
                                </Tooltip>
                              )}
                              {aiAnalysis.data_flow_summary && (
                                <Tooltip title={aiAnalysis.data_flow_summary}>
                                  <Chip
                                    size="small"
                                    label="📊"
                                    sx={{
                                      bgcolor: alpha(theme.palette.success.main, 0.15),
                                      color: theme.palette.success.main,
                                      fontSize: "0.65rem",
                                      height: 20,
                                      cursor: "help",
                                    }}
                                  />
                                </Tooltip>
                              )}
                            </Stack>
                          )}
                        </TableCell>
                        <TableCell>
                          <FindingNotesBadge findingId={finding.id} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Box>
      )}

      {/* Tab Panel: Codebase Map */}
      {activeTab === 1 && (
        <Box sx={{ mb: 4 }}>
          <CodebaseMapView 
            reportId={id} 
            projectId={reportQuery.data?.project_id || 0}
            availableReports={projectReportsQuery.data?.map(r => ({ id: r.id, created_at: r.created_at })) || []}
          />
        </Box>
      )}

      {/* Tab Panel: Exploitability Analysis */}
      {activeTab === 2 && (
        <Box>
          {/* Attack Chains Section */}
          {aiInsightsQuery.data && aiInsightsQuery.data.attack_chains.length > 0 && (
            <Paper
              sx={{
                p: 3,
                mb: 3,
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.08)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                borderRadius: 2,
              }}
            >
              <Typography variant="h6" fontWeight={700} sx={{ mb: 2, display: "flex", alignItems: "center", gap: 1 }}>
                ⛓️ Attack Chains Identified
                <Chip 
                  size="small" 
                  label={aiInsightsQuery.data.attack_chains.length}
                  sx={{ 
                    bgcolor: alpha(theme.palette.error.main, 0.15),
                    color: theme.palette.error.main,
                    fontWeight: 700,
                  }}
                />
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                These vulnerabilities can be chained together for greater impact.
              </Typography>
              <Grid container spacing={2}>
                {aiInsightsQuery.data.attack_chains.map((chain: AttackChain, idx: number) => {
                  const chainConfig = getSeverityConfig(chain.severity || "high", theme);
                  return (
                    <Grid item xs={12} md={6} key={idx}>
                      <Card
                        sx={{
                          borderLeft: `4px solid ${chainConfig.color}`,
                          bgcolor: alpha(chainConfig.color, 0.03),
                        }}
                      >
                        <CardContent>
                          <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                            <Chip
                              label={chainConfig.label}
                              size="small"
                              sx={{ bgcolor: chainConfig.bg, color: chainConfig.color, fontWeight: 600 }}
                            />
                            <Chip
                              label={`${chain.likelihood} likelihood`}
                              size="small"
                              variant="outlined"
                              sx={{ fontSize: "0.7rem" }}
                            />
                          </Stack>
                          <Typography variant="subtitle1" fontWeight={700} sx={{ mb: 1 }}>
                            {chain.title}
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                            {chain.description}
                          </Typography>
                          <Typography variant="body2" sx={{ mt: 1 }}>
                            <strong>Impact:</strong> {chain.impact}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                            Involves {chain.finding_ids.length} finding{chain.finding_ids.length !== 1 ? "s" : ""}
                          </Typography>
                        </CardContent>
                      </Card>
                    </Grid>
                  );
                })}
              </Grid>
            </Paper>
          )}

          {/* AI Insights Summary */}
          {aiInsightsQuery.data && ((aiInsightsQuery.data.agentic_corroborated ?? 0) > 0 || aiInsightsQuery.data.severity_adjustments > 0) && (
            <Paper
              sx={{
                p: 2,
                mb: 3,
                bgcolor: alpha(theme.palette.info.main, 0.05),
                border: `1px solid ${alpha(theme.palette.info.main, 0.2)}`,
                borderRadius: 2,
              }}
            >
              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1, display: "flex", alignItems: "center", gap: 1 }}>
                🤖 AI Analysis Summary
              </Typography>
              <Stack direction="row" spacing={2} flexWrap="wrap" sx={{ mb: 1 }}>
                {aiInsightsQuery.data.findings_analyzed > 0 && (
                  <Chip 
                    size="small" 
                    label={`${aiInsightsQuery.data.findings_analyzed} findings analyzed`}
                    sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}
                  />
                )}
                {(aiInsightsQuery.data.agentic_corroborated ?? 0) > 0 && (
                  <Tooltip title="High-confidence vulnerabilities confirmed by deep AI analysis">
                    <Chip 
                      size="small" 
                      icon={<span style={{ fontSize: "0.8rem", marginLeft: 4 }}>✓</span>}
                      label={`${aiInsightsQuery.data.agentic_corroborated} high-confidence findings`}
                      sx={{ bgcolor: alpha(theme.palette.success.main, 0.15), color: theme.palette.success.dark, cursor: "help" }}
                    />
                  </Tooltip>
                )}
                {aiInsightsQuery.data.severity_adjustments > 0 && (
                  <Chip 
                    size="small" 
                    label={`${aiInsightsQuery.data.severity_adjustments} severity adjustments`}
                    sx={{ bgcolor: alpha(theme.palette.info.main, 0.15), color: theme.palette.info.dark }}
                  />
                )}
              </Stack>
              {(aiInsightsQuery.data.agentic_findings_count ?? 0) > 0 && (
                <Typography variant="caption" color="text.secondary">
                  AI found {aiInsightsQuery.data.agentic_findings_count} additional vulnerabilities through deep code analysis
                </Typography>
              )}
              {((aiInsightsQuery.data.filtered_count ?? 0) > 0 || aiInsightsQuery.data.false_positive_count > 0) && (
                <Typography variant="caption" color="text.disabled" sx={{ display: "block", mt: 0.5 }}>
                  Lower confidence findings are shown at the bottom in grey
                </Typography>
              )}
            </Paper>
          )}

          {/* Attack Chain Diagram - Visual exploit path map */}
          {attackChainDiagramQuery.data && attackChainDiagramQuery.data.diagram && (
            <Paper
              sx={{
                p: 3,
                mb: 3,
                background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.05)} 0%, ${alpha(theme.palette.warning.main, 0.03)} 100%)`,
                border: `1px solid ${alpha(theme.palette.error.main, 0.15)}`,
                borderRadius: 2,
              }}
            >
              <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 2 }}>
                <Typography variant="h6" fontWeight={700} sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  🗺️ Attack Chain Map
                  {attackChainDiagramQuery.data.generated_by === "ai" && (
                    <Chip 
                      size="small" 
                      label="AI Generated"
                      sx={{ 
                        bgcolor: alpha(theme.palette.info.main, 0.15),
                        color: theme.palette.info.main,
                        fontSize: "0.7rem",
                      }}
                    />
                  )}
                </Typography>
                <Tooltip title="Regenerate diagram">
                  <IconButton 
                    size="small"
                    onClick={() => {
                      api.clearAttackChainDiagram(id).then(() => {
                        queryClient.invalidateQueries({ queryKey: ["attack-chain-diagram", id] });
                      });
                    }}
                  >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                      <path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z" />
                    </svg>
                  </IconButton>
                </Tooltip>
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Visual representation of how vulnerabilities can be chained for exploitation.
              </Typography>
              <Box sx={{ 
                bgcolor: "background.paper", 
                borderRadius: 1, 
                p: 2,
                border: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
                minHeight: 300,
              }}>
                <MermaidDiagram code={attackChainDiagramQuery.data.diagram} />
              </Box>
            </Paper>
          )}

          {attackChainDiagramQuery.isLoading && exploitQuery.data && exploitQuery.data.length > 0 && (
            <Paper sx={{ p: 3, mb: 3 }}>
              <Typography variant="subtitle2" sx={{ mb: 2 }}>🗺️ Generating Attack Chain Map...</Typography>
              <Skeleton variant="rectangular" height={200} sx={{ borderRadius: 1 }} />
            </Paper>
          )}

          {exploitQuery.isLoading && (
            <Paper sx={{ p: 3 }}>
              <Skeleton variant="rectangular" height={100} />
            </Paper>
          )}

          {exploitQuery.data && exploitQuery.data.length === 0 && !pollExploit && (
            <Paper
              sx={{
                p: 4,
                textAlign: "center",
                bgcolor: alpha(theme.palette.info.main, 0.05),
                border: `1px dashed ${alpha(theme.palette.info.main, 0.3)}`,
              }}
            >
              <Typography color="text.secondary" sx={{ mb: 2 }}>
                Generate AI-powered exploitability narratives for high and critical findings.
              </Typography>
              
              {/* Mode selector */}
              <Stack direction="row" spacing={1} justifyContent="center" sx={{ mb: 2 }}>
                <Button
                  variant={exploitMode === "summary" ? "contained" : "outlined"}
                  size="small"
                  onClick={() => setExploitMode("summary")}
                  sx={{ 
                    minWidth: 100,
                    ...(exploitMode === "summary" && {
                      background: `linear-gradient(135deg, ${theme.palette.success.main} 0%, ${theme.palette.success.dark} 100%)`,
                    })
                  }}
                >
                  Fast
                </Button>
                <Button
                  variant={exploitMode === "auto" ? "contained" : "outlined"}
                  size="small"
                  onClick={() => setExploitMode("auto")}
                  sx={{ 
                    minWidth: 100,
                    ...(exploitMode === "auto" && {
                      background: `linear-gradient(135deg, ${theme.palette.info.main} 0%, ${theme.palette.info.dark} 100%)`,
                    })
                  }}
                >
                  Auto
                </Button>
                <Button
                  variant={exploitMode === "full" ? "contained" : "outlined"}
                  size="small"
                  onClick={() => setExploitMode("full")}
                  sx={{ 
                    minWidth: 100,
                    ...(exploitMode === "full" && {
                      background: `linear-gradient(135deg, ${theme.palette.warning.main} 0%, ${theme.palette.warning.dark} 100%)`,
                    })
                  }}
                >
                  Detailed
                </Button>
              </Stack>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 2 }}>
                {exploitMode === "summary" && "⚡ Fast: 1 AI call for executive summary + template-based scenarios"}
                {exploitMode === "auto" && "🔄 Auto: Chooses based on finding count (≤15 = detailed, >15 = fast)"}
                {exploitMode === "full" && "🔍 Detailed: Individual AI analysis per finding (slower but more thorough)"}
              </Typography>

              <Button
                variant="contained"
                onClick={() => startExploitMutation.mutate()}
                disabled={startExploitMutation.isPending}
                sx={{
                  background: `linear-gradient(135deg, ${theme.palette.error.main} 0%, ${theme.palette.error.dark} 100%)`,
                }}
              >
                {startExploitMutation.isPending ? "Starting..." : "Generate Analysis"}
              </Button>
            </Paper>
          )}

          {pollExploit && (
            <Paper sx={{ p: 4, textAlign: "center" }}>
              <CircularProgress size={40} sx={{ mb: 2 }} />
              <Typography color="text.secondary">
                Generating exploit scenarios... This may take a moment.
              </Typography>
              <LinearProgress sx={{ mt: 2, maxWidth: 300, mx: "auto" }} />
            </Paper>
          )}

          {exploitQuery.data && exploitQuery.data.length > 0 && (
            <Grid container spacing={2}>
              {exploitQuery.data.map((scenario: ExploitScenario) => {
                const config = getSeverityConfig(scenario.severity || "info", theme);
                return (
                  <Grid item xs={12} key={scenario.id}>
                    <Card 
                      sx={{ 
                        borderLeft: `4px solid ${config.color}`,
                        ...(scenario.title === "Exploit Development Summary" && {
                          background: `linear-gradient(135deg, ${alpha(theme.palette.error.main, 0.08)} 0%, ${alpha(theme.palette.warning.main, 0.05)} 100%)`,
                          border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`,
                          borderLeft: `4px solid ${theme.palette.error.main}`,
                        })
                      }}
                    >
                      <CardContent>
                        <Stack direction="row" spacing={2} alignItems="flex-start" sx={{ mb: 2 }}>
                          <Chip
                            label={config.label}
                            size="small"
                            sx={{ bgcolor: config.bg, color: config.color, fontWeight: 600 }}
                          />
                          <Typography 
                            variant="h6" 
                            fontWeight={700}
                            sx={scenario.title === "Exploit Development Summary" ? { color: "error.main" } : {}}
                          >
                            {scenario.title}
                          </Typography>
                        </Stack>

                        <Grid container spacing={3}>
                          <Grid item xs={12} md={scenario.title === "Exploit Development Summary" ? 12 : 6}>
                            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                              {scenario.title === "Exploit Development Summary" ? "Exploitation Overview" : "Attack Narrative"}
                            </Typography>
                            <Box
                              sx={{
                                fontSize: "0.875rem",
                                color: "text.secondary",
                                lineHeight: 1.7,
                                "& .section-header": {
                                  color: "text.primary",
                                  fontWeight: 700,
                                  fontSize: "0.9rem",
                                  display: "block",
                                  mt: 2,
                                  mb: 0.5,
                                },
                                "& .section-header:first-of-type": { mt: 0 },
                                "& strong": { color: "text.primary", fontWeight: 600 },
                                "& ul, & ol": { m: 0, pl: 2.5, "& li": { mb: 0.5 } },
                                "& p": { m: 0, mb: 1 },
                              }}
                              dangerouslySetInnerHTML={{
                                __html: (() => {
                                  let html = scenario.narrative || "";
                                  // Section headers
                                  html = html.replace(/^\*\*([^*]+)\*\*$/gm, '<span class="section-header">$1</span>');
                                  // Inline bold
                                  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
                                  // Bullets
                                  html = html.replace(/((?:^[•\-\*]\s+.+$\n?)+)/gm, (match) => {
                                    const items = match.trim().split("\n")
                                      .map(line => line.replace(/^[•\-\*]\s+/, "").trim())
                                      .filter(Boolean)
                                      .map(item => `<li>${item}</li>`).join("");
                                    return `<ul>${items}</ul>`;
                                  });
                                  // Numbers
                                  html = html.replace(/((?:^\d+\.\s+.+$\n?)+)/gm, (match) => {
                                    const items = match.trim().split("\n")
                                      .map(line => line.replace(/^\d+\.\s+/, "").trim())
                                      .filter(Boolean)
                                      .map(item => `<li>${item}</li>`).join("");
                                    return `<ol>${items}</ol>`;
                                  });
                                  // Paragraphs
                                  html = html.replace(/\n\n+/g, "</p><p>");
                                  if (!html.startsWith("<")) html = "<p>" + html;
                                  if (!html.endsWith(">")) html = html + "</p>";
                                  html = html.replace(/<p>\s*<\/p>/g, "");
                                  html = html.replace(/<p>\s*(<(?:ul|ol|span))/g, "$1");
                                  html = html.replace(/(<\/(?:ul|ol|span)>)\s*<\/p>/g, "$1");
                                  return html;
                                })()
                              }}
                            />
                          </Grid>
                          {scenario.title !== "Exploit Development Summary" && (
                            <Grid item xs={12} md={6}>
                              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                Impact
                              </Typography>
                              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>{scenario.impact}</Typography>
                            </Grid>
                          )}
                          
                          {/* Attack Complexity & Maturity Badges */}
                          {scenario.title !== "Exploit Development Summary" && (scenario.attack_complexity || scenario.exploit_maturity) && (
                            <Grid item xs={12}>
                              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                                {scenario.attack_complexity && (
                                  <Chip
                                    size="small"
                                    label={`Complexity: ${scenario.attack_complexity}`}
                                    sx={{
                                      bgcolor: scenario.attack_complexity === "Low" 
                                        ? alpha(theme.palette.error.main, 0.15) 
                                        : scenario.attack_complexity === "Medium"
                                        ? alpha(theme.palette.warning.main, 0.15)
                                        : alpha(theme.palette.success.main, 0.15),
                                      color: scenario.attack_complexity === "Low"
                                        ? theme.palette.error.main
                                        : scenario.attack_complexity === "Medium"
                                        ? theme.palette.warning.main
                                        : theme.palette.success.main,
                                      fontWeight: 600,
                                    }}
                                  />
                                )}
                                {scenario.exploit_maturity && (
                                  <Chip
                                    size="small"
                                    label={`Maturity: ${scenario.exploit_maturity}`}
                                    sx={{
                                      bgcolor: scenario.exploit_maturity === "High"
                                        ? alpha(theme.palette.error.main, 0.15)
                                        : scenario.exploit_maturity === "Functional"
                                        ? alpha(theme.palette.warning.main, 0.15)
                                        : alpha(theme.palette.info.main, 0.15),
                                      color: scenario.exploit_maturity === "High"
                                        ? theme.palette.error.main
                                        : scenario.exploit_maturity === "Functional"
                                        ? theme.palette.warning.main
                                        : theme.palette.info.main,
                                      fontWeight: 600,
                                    }}
                                  />
                                )}
                              </Stack>
                            </Grid>
                          )}
                          
                          <Grid item xs={12} md={6}>
                            <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                              Proof of Concept Outline
                            </Typography>
                            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                              <Typography
                                variant="body2"
                                sx={{ fontFamily: "monospace", whiteSpace: "pre-wrap" }}
                              >
                                {scenario.poc_outline}
                              </Typography>
                            </Paper>
                          </Grid>
                          
                          {/* POC Scripts Section */}
                          {scenario.poc_scripts && Object.keys(scenario.poc_scripts).length > 0 && !scenario.poc_scripts.note && (
                            <Grid item xs={12}>
                              <Typography variant="subtitle2" color="error.main" gutterBottom sx={{ fontWeight: 700 }}>
                                🔥 Executable POC Scripts
                              </Typography>
                              <Paper sx={{ bgcolor: alpha(theme.palette.grey[900], 0.9), borderRadius: 2, overflow: "hidden" }}>
                                <Tabs
                                  value={0}
                                  variant="scrollable"
                                  scrollButtons="auto"
                                  sx={{
                                    bgcolor: alpha(theme.palette.grey[800], 0.8),
                                    minHeight: 36,
                                    "& .MuiTab-root": { minHeight: 36, py: 0.5, fontSize: "0.75rem", color: "grey.400" },
                                    "& .Mui-selected": { color: "error.main" },
                                  }}
                                >
                                  {Object.keys(scenario.poc_scripts).map((lang, idx) => (
                                    <Tab key={lang} label={lang.toUpperCase()} value={idx} />
                                  ))}
                                </Tabs>
                                {Object.entries(scenario.poc_scripts).map(([lang, script], idx) => (
                                  <Box key={lang} sx={{ display: idx === 0 ? "block" : "none" }}>
                                    <Box sx={{ position: "relative" }}>
                                      <IconButton
                                        size="small"
                                        onClick={() => navigator.clipboard.writeText(script)}
                                        sx={{ position: "absolute", top: 8, right: 8, color: "grey.500", "&:hover": { color: "white" } }}
                                        title="Copy to clipboard"
                                      >
                                        <CopyIcon />
                                      </IconButton>
                                      <Box
                                        component="pre"
                                        sx={{
                                          p: 2,
                                          m: 0,
                                          overflow: "auto",
                                          maxHeight: 400,
                                          fontSize: "0.75rem",
                                          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
                                          color: "#e6e6e6",
                                          "& .comment": { color: "#6a9955" },
                                          lineHeight: 1.5,
                                        }}
                                      >
                                        <code>{script}</code>
                                      </Box>
                                    </Box>
                                  </Box>
                                ))}
                              </Paper>
                              <Typography variant="caption" color="warning.main" sx={{ display: "block", mt: 1 }}>
                                ⚠️ Use only for authorized security testing. Unauthorized use is illegal.
                              </Typography>
                            </Grid>
                          )}
                          
                          {scenario.title !== "Exploit Development Summary" && (
                            <Grid item xs={12} md={6}>
                              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                                Mitigation
                              </Typography>
                              <Alert severity="info" sx={{ bgcolor: alpha(theme.palette.success.main, 0.1) }}>
                                {scenario.mitigation_notes}
                              </Alert>
                            </Grid>
                          )}
                        </Grid>
                      </CardContent>
                    </Card>
                  </Grid>
                );
              })}
            </Grid>
          )}
        </Box>
      )}

      {/* Chat Window - Visible on Findings and Exploitability tabs */}
      {(activeTab === 0 || activeTab === 2) && findingsQuery.data && (
        <Paper
          sx={{
            position: "fixed",
            bottom: 0,
            right: 24,
            width: chatOpen ? 450 : 200,
            maxHeight: chatOpen ? "60vh" : "auto",
            zIndex: 1200,
            borderRadius: "12px 12px 0 0",
            boxShadow: "0 -4px 20px rgba(0,0,0,0.15)",
            overflow: "hidden",
            transition: "all 0.3s ease",
          }}
        >
          {/* Chat Header */}
          <Box
            onClick={() => setChatOpen(!chatOpen)}
            sx={{
              p: 2,
              bgcolor: activeTab === 2 ? theme.palette.error.main : theme.palette.primary.main,
              color: "white",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              "&:hover": { 
                bgcolor: activeTab === 2 ? theme.palette.error.dark : theme.palette.primary.dark 
              },
            }}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ChatIcon />
              <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                Ask About {activeTab === 2 ? "Exploits" : "Findings"}
              </Typography>
            </Box>
            <IconButton size="small" sx={{ color: "white" }}>
              {chatOpen ? <ExpandMoreIcon /> : <ExpandLessIcon />}
            </IconButton>
          </Box>

          {/* Chat Content */}
          <Collapse in={chatOpen}>
            {/* Messages Area */}
            <Box
              sx={{
                height: "calc(60vh - 140px)",
                maxHeight: 400,
                overflowY: "auto",
                p: 2,
                bgcolor: alpha(theme.palette.background.default, 0.5),
              }}
            >
              {/* Welcome message */}
              {chatMessages.length === 0 && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <SmartToyIcon />
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2, mt: 1 }}>
                    Ask me anything about these {activeTab === 2 ? "exploit scenarios" : "security findings"}!
                  </Typography>
                  <Box sx={{ display: "flex", flexDirection: "column", gap: 1 }}>
                    {(activeTab === 2
                      ? [
                          "Which exploit has the highest impact?",
                          "Summarize the attack narratives",
                          "What should I fix first?",
                          "How can I prevent these attacks?",
                        ]
                      : [
                          "What's the most critical vulnerability?",
                          "Show me SQL injection findings",
                          "Which files have the most issues?",
                          "Summarize the security posture",
                        ]
                    ).map((suggestion, i) => (
                      <Chip
                        key={i}
                        label={suggestion}
                        variant="outlined"
                        size="small"
                        onClick={() => setChatInput(suggestion)}
                        sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                      />
                    ))}
                  </Box>
                </Box>
              )}

              {/* Chat Messages */}
              {chatMessages.map((msg, i) => (
                <Box
                  key={i}
                  sx={{
                    display: "flex",
                    justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
                    mb: 2,
                  }}
                >
                  <Box
                    sx={{
                      maxWidth: "85%",
                      display: "flex",
                      gap: 1,
                      flexDirection: msg.role === "user" ? "row-reverse" : "row",
                    }}
                  >
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        flexShrink: 0,
                      }}
                    >
                      {msg.role === "user" ? (
                        <PersonIcon />
                      ) : (
                        <SmartToyIcon />
                      )}
                    </Box>
                    <Paper
                      sx={{
                        p: 1.5,
                        bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.background.paper,
                        color: msg.role === "user" ? "white" : "text.primary",
                        borderRadius: 2,
                        "& p": { m: 0 },
                        "& p:not(:last-child)": { mb: 1 },
                        "& code": {
                          bgcolor: alpha(msg.role === "user" ? "#fff" : theme.palette.primary.main, 0.2),
                          px: 0.5,
                          borderRadius: 0.5,
                          fontFamily: "monospace",
                          fontSize: "0.85em",
                        },
                        "& ul, & ol": { pl: 2, m: 0 },
                        "& li": { mb: 0.5 },
                      }}
                    >
                      <ReactMarkdown>{msg.content}</ReactMarkdown>
                    </Paper>
                  </Box>
                </Box>
              ))}

              {/* Loading indicator */}
              {chatLoading && (
                <Box sx={{ display: "flex", justifyContent: "flex-start", mb: 2 }}>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Box
                      sx={{
                        width: 32,
                        height: 32,
                        borderRadius: "50%",
                        bgcolor: theme.palette.secondary.main,
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                      }}
                    >
                      <SmartToyIcon />
                    </Box>
                    <Paper sx={{ p: 1.5, borderRadius: 2 }}>
                      <Box sx={{ display: "flex", gap: 0.5 }}>
                        <CircularProgress size={8} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.2s" }} />
                        <CircularProgress size={8} sx={{ animationDelay: "0.4s" }} />
                      </Box>
                    </Paper>
                  </Box>
                </Box>
              )}

              {/* Error message */}
              {chatError && (
                <Alert severity="error" sx={{ mb: 2 }} onClose={() => setChatError(null)}>
                  {chatError}
                </Alert>
              )}

              <div ref={chatEndRef} />
            </Box>

            {/* Input Area */}
            <Box
              sx={{
                p: 2,
                borderTop: `1px solid ${theme.palette.divider}`,
                bgcolor: theme.palette.background.paper,
              }}
            >
              <Box sx={{ display: "flex", gap: 1 }}>
                <TextField
                  fullWidth
                  size="small"
                  placeholder={`Ask about ${activeTab === 2 ? "exploits" : "findings"}...`}
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  onKeyDown={handleChatKeyDown}
                  disabled={chatLoading}
                  multiline
                  maxRows={3}
                  sx={{
                    "& .MuiOutlinedInput-root": {
                      borderRadius: 2,
                    },
                  }}
                />
                <IconButton
                  color="primary"
                  onClick={handleSendMessage}
                  disabled={!chatInput.trim() || chatLoading}
                  sx={{
                    bgcolor: theme.palette.primary.main,
                    color: "white",
                    "&:hover": { bgcolor: theme.palette.primary.dark },
                    "&:disabled": { bgcolor: theme.palette.action.disabledBackground },
                  }}
                >
                  <SendIcon />
                </IconButton>
              </Box>
            </Box>
          </Collapse>
        </Paper>
      )}
    </Box>
  );
}
