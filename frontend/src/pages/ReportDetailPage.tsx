import { useEffect, useMemo, useState, useRef, useCallback } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
} from "@mui/material";
import { useNavigate, useParams } from "react-router-dom";
import { api, AIInsights, AttackChain, ChatMessage, CodebaseFile, CodebaseFolder, CodebaseNode, CodebaseSummary, ExploitScenario, Finding } from "../api/client";
import ReactMarkdown from "react-markdown";

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

// Language color mapping
const getLanguageColor = (language: string | undefined, theme: Theme) => {
  const colors: Record<string, string> = {
    python: "#3572A5",
    javascript: "#f1e05a",
    typescript: "#3178c6",
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
    html: "#e34c26",
    css: "#563d7c",
    json: "#292929",
    yaml: "#cb171e",
    markdown: "#083fa1",
    sql: "#e38c00",
    shell: "#89e051",
    dockerfile: "#384d54",
  };
  return colors[language?.toLowerCase() || ""] || theme.palette.grey[500];
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
            label={file.language || "Unknown"} 
            size="small"
            sx={{ 
              bgcolor: alpha(getLanguageColor(file.language, theme), 0.15),
              color: getLanguageColor(file.language, theme),
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
}

function TreeNode({ node, depth, expandedFolders, onToggleFolder, onShowMetadata, searchQuery = "" }: TreeNodeProps) {
  const theme = useTheme();
  const isFolder = node.type === "folder";
  const isExpanded = isFolder && expandedFolders.has(node.path);
  
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

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          py: 0.5,
          px: 1,
          pl: depth * 2 + 1,
          cursor: isFolder ? "pointer" : "default",
          borderRadius: 1,
          transition: "all 0.15s ease",
          "&:hover": {
            bgcolor: alpha(theme.palette.primary.main, 0.05),
          },
        }}
        onClick={() => isFolder && onToggleFolder(node.path)}
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
            fontSize: "0.8rem",
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
}

// Severity filter type
type SeverityFilter = "all" | "critical" | "high" | "medium" | "low";

function CodebaseMapView({ reportId }: CodebaseMapViewProps) {
  const theme = useTheme();
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());
  const [selectedFile, setSelectedFile] = useState<CodebaseFile | null>(null);
  const [metadataOpen, setMetadataOpen] = useState(false);
  
  // Quick win states
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [selectedLanguages, setSelectedLanguages] = useState<Set<string>>(new Set());
  const [showStats, setShowStats] = useState(true);

  const codebaseQuery = useQuery({
    queryKey: ["codebase", reportId],
    queryFn: () => api.getCodebaseStructure(reportId),
    enabled: !!reportId,
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
      const lang = file.language || "Unknown";
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
    return selectedLanguages.has((node as CodebaseFile).language || "Unknown");
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
          {/* Fuzzy File Search (Quick Win #1) */}
          <Grid item xs={12} md={5}>
            <TextField
              fullWidth
              size="small"
              placeholder="Search files... (e.g., auth, .py, service)"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon />
                  </InputAdornment>
                ),
                endAdornment: searchQuery && (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setSearchQuery("")}>
                      <ClearIcon />
                    </IconButton>
                  </InputAdornment>
                ),
              }}
              sx={{
                "& .MuiOutlinedInput-root": {
                  bgcolor: theme.palette.background.paper,
                },
              }}
            />
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

      {/* Tree Controls */}
      <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
        <Button size="small" variant="outlined" onClick={handleExpandAll}>
          Expand All
        </Button>
        <Button size="small" variant="outlined" onClick={handleCollapseAll}>
          Collapse All
        </Button>
      </Stack>

      {/* File Tree */}
      <Paper
        sx={{
          p: 2,
          bgcolor: alpha(theme.palette.background.paper, 0.5),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 2,
          maxHeight: 500,
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
            />
          ))
        )}
      </Paper>

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

  // Sort findings
  const sortedFindings = useMemo(() => {
    if (!findingsQuery.data) return [];
    
    return [...findingsQuery.data].sort((a, b) => {
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
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sortedFindings.map((finding, idx) => {
                    const config = getSeverityConfig(finding.severity, theme);
                    // AI analysis data from details
                    const aiAnalysis = finding.details?.ai_analysis as {
                      is_false_positive?: boolean;
                      false_positive_reason?: string;
                      severity_adjusted?: boolean;
                      original_severity?: string;
                      severity_reason?: string;
                      duplicate_group?: string;
                      attack_chain?: string;
                      data_flow_summary?: string;
                    } | undefined;
                    return (
                      <TableRow
                        key={finding.id}
                        sx={{
                          animation: `${fadeIn} 0.3s ease ${idx * 0.03}s both`,
                          "&:hover": {
                            bgcolor: alpha(theme.palette.primary.main, 0.03),
                          },
                          // Dim false positives
                          opacity: aiAnalysis?.is_false_positive ? 0.6 : 1,
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
                            label={finding.type}
                            size="small"
                            variant="outlined"
                            sx={{ fontWeight: 500 }}
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
                              {aiAnalysis.is_false_positive && (
                                <Tooltip title={`Likely false positive: ${aiAnalysis.false_positive_reason || 'Context suggests low risk'}`}>
                                  <Chip
                                    size="small"
                                    label="FP?"
                                    sx={{
                                      bgcolor: alpha(theme.palette.warning.main, 0.15),
                                      color: theme.palette.warning.main,
                                      fontSize: "0.65rem",
                                      height: 20,
                                      cursor: "help",
                                    }}
                                  />
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
          <CodebaseMapView reportId={id} />
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
          {aiInsightsQuery.data && (aiInsightsQuery.data.false_positive_count > 0 || aiInsightsQuery.data.severity_adjustments > 0) && (
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
              <Stack direction="row" spacing={2} flexWrap="wrap">
                {aiInsightsQuery.data.findings_analyzed > 0 && (
                  <Chip 
                    size="small" 
                    label={`${aiInsightsQuery.data.findings_analyzed} findings analyzed`}
                    sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}
                  />
                )}
                {aiInsightsQuery.data.false_positive_count > 0 && (
                  <Chip 
                    size="small" 
                    label={`${aiInsightsQuery.data.false_positive_count} likely false positives`}
                    sx={{ bgcolor: alpha(theme.palette.warning.main, 0.15), color: theme.palette.warning.dark }}
                  />
                )}
                {aiInsightsQuery.data.severity_adjustments > 0 && (
                  <Chip 
                    size="small" 
                    label={`${aiInsightsQuery.data.severity_adjustments} severity adjustments`}
                    sx={{ bgcolor: alpha(theme.palette.info.main, 0.15), color: theme.palette.info.dark }}
                  />
                )}
              </Stack>
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
