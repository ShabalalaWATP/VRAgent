/**
 * ReverseEngineeringHub - Interactive Reverse Engineering Analysis Page
 *
 * Provides tools for:
 * - Binary Analysis (EXE, ELF, DLL) - Extract strings, imports, metadata
 * - APK Analysis - Android app analysis with permission/security checks
 * - Docker Layer Analysis - Find secrets in image layers
 */

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Box,
  Container,
  Typography,
  Card,
  CardContent,
  Grid,
  Button,
  Alert,
  CircularProgress,
  Tabs,
  Tab,
  Paper,
  Chip,
  IconButton,
  Tooltip,
  LinearProgress,
  alpha,
  useTheme,
  Divider,
  TextField,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  FormControlLabel,
  FormControl,
  Select,
  Switch,
  Breadcrumbs,
  Link as MuiLink,
  Autocomplete,
  Menu,
  MenuItem,
} from "@mui/material";
import { Link, useSearchParams } from "react-router-dom";
import {
  CloudUpload as UploadIcon,
  Memory as BinaryIcon,
  Android as ApkIcon,
  Storage as DockerIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckIcon,
  Code as CodeIcon,
  VpnKey as SecretIcon,
  Functions as FunctionIcon,
  Layers as LayersIcon,
  SmartToy as AiIcon,
  Refresh as RefreshIcon,
  Home as HomeIcon,
  BugReport as BugIcon,
  Lock as LockIcon,
  Shield as ShieldIcon,
  Info as InfoIcon,
  Search as SearchIcon,
  Save as SaveIcon,
  History as HistoryIcon,
  Delete as DeleteIcon,
  Visibility as ViewIcon,
  NavigateBefore as PrevIcon,
  NavigateNext as NextIcon,
  FirstPage as FirstPageIcon,
  LastPage as LastPageIcon,
  DataObject as HexIcon,
  InsertLink as LinkIcon,
  Folder as StorageIcon,
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Description as DocIcon,
  PictureAsPdf as PdfIcon,
  Article as ArticleIcon,
  TextSnippet as WordIcon,
} from "@mui/icons-material";
import {
  reverseEngineeringClient,
  type ReverseEngineeringStatus,
  type BinaryAnalysisResult,
  type ApkAnalysisResult,
  type ApkCertificate,
  type DockerAnalysisResult,
  type DockerImageInfo,
  type REReportSummary,
  type SaveREReportRequest,
  type HexViewResult,
  type HexSearchResponse,
  type DataFlowAnalysisResult,
  type JadxDecompilationResult,
  type AIVulnScanResult,
} from "../api/client";
import { MermaidDiagram } from "../components/MermaidDiagram";

// Advanced APK Analysis Components
import { JadxDecompiler, ManifestVisualizer, AttackSurfaceMap, ObfuscationAnalyzer } from "../components/ApkAdvancedAnalysis";

// Advanced Binary Analysis Components
import { EntropyVisualizer } from "../components/BinaryAdvancedAnalysis";

// Severity colors
const getSeverityColor = (severity: string): string => {
  switch (severity.toLowerCase()) {
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

// Tab panel component
interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`re-tabpanel-${index}`}
      aria-labelledby={`re-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

// File drop zone component
interface FileDropZoneProps {
  accept: string;
  onFileSelect: (file: File) => void;
  label: string;
  description: string;
  icon: React.ReactNode;
  disabled?: boolean;
}

function FileDropZone({
  accept,
  onFileSelect,
  label,
  description,
  icon,
  disabled = false,
}: FileDropZoneProps) {
  const theme = useTheme();
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    if (!disabled) setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFileSelect(files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <Box
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      sx={{
        border: `2px dashed ${isDragging ? theme.palette.primary.main : theme.palette.divider}`,
        borderRadius: 2,
        p: 4,
        textAlign: "center",
        cursor: disabled ? "not-allowed" : "pointer",
        transition: "all 0.2s",
        bgcolor: isDragging
          ? alpha(theme.palette.primary.main, 0.1)
          : "transparent",
        opacity: disabled ? 0.5 : 1,
        "&:hover": disabled
          ? {}
          : {
              borderColor: theme.palette.primary.main,
              bgcolor: alpha(theme.palette.primary.main, 0.05),
            },
      }}
      component="label"
    >
      <input
        type="file"
        accept={accept}
        onChange={handleFileChange}
        hidden
        disabled={disabled}
      />
      <Box sx={{ color: theme.palette.primary.main, mb: 2 }}>{icon}</Box>
      <Typography variant="h6" gutterBottom>
        {label}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {description}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
        Drag & drop or click to browse
      </Typography>
    </Box>
  );
}

// Binary Analysis Results Component
function BinaryResults({ result }: { result: BinaryAnalysisResult }) {
  const theme = useTheme();
  const [stringsExpanded, setStringsExpanded] = useState(false);

  return (
    <Box>
      {/* Metadata Section */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <BinaryIcon color="primary" /> Binary Metadata
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">File Type</Typography>
            <Typography variant="body1">{result.metadata.file_type}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Architecture</Typography>
            <Typography variant="body1">{result.metadata.architecture}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">File Size</Typography>
            <Typography variant="body1">{(result.metadata.file_size / 1024).toFixed(1)} KB</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Entry Point</Typography>
            <Typography variant="body1" fontFamily="monospace">
              {result.metadata.entry_point ? `0x${result.metadata.entry_point.toString(16)}` : "N/A"}
            </Typography>
          </Grid>
          {result.metadata.is_packed && (
            <Grid item xs={12}>
              <Chip
                icon={<WarningIcon />}
                label={`Packed binary detected: ${result.metadata.packer_name || "Unknown packer"}`}
                color="warning"
                variant="outlined"
              />
            </Grid>
          )}
          {result.metadata.compile_time && (
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Compile Time</Typography>
              <Typography variant="body1">{result.metadata.compile_time}</Typography>
            </Grid>
          )}
        </Grid>
      </Paper>

      {/* Suspicious Indicators */}
      {result.suspicious_indicators.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon color="error" /> Suspicious Indicators ({result.suspicious_indicators.length})
          </Typography>
          <List dense>
            {result.suspicious_indicators.map((indicator, idx) => (
              <ListItem key={idx}>
                <ListItemIcon>
                  <Chip
                    label={indicator.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(getSeverityColor(indicator.severity), 0.2),
                      color: getSeverityColor(indicator.severity),
                      fontWeight: 600,
                    }}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={indicator.description}
                  secondary={indicator.category}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Secrets Found */}
      {result.secrets.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecretIcon color="error" /> Secrets Found ({result.secrets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Severity</TableCell>
                  <TableCell>Offset</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.secrets.map((secret, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{secret.type}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                        {secret.masked_value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={secret.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                          color: getSeverityColor(secret.severity),
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {secret.offset ? `0x${secret.offset.toString(16)}` : "-"}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Imports */}
      {result.imports.length > 0 && (
        <Accordion defaultExpanded={result.imports.some(i => i.is_suspicious)}>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <FunctionIcon color="primary" /> Imported Functions ({result.imports.length})
              {result.imports.filter(i => i.is_suspicious).length > 0 && (
                <Chip
                  label={`${result.imports.filter(i => i.is_suspicious).length} suspicious`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Function</TableCell>
                    <TableCell>Library</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.imports
                    .sort((a, b) => (b.is_suspicious ? 1 : 0) - (a.is_suspicious ? 1 : 0))
                    .map((imp, idx) => (
                      <TableRow
                        key={idx}
                        sx={{
                          bgcolor: imp.is_suspicious
                            ? alpha(theme.palette.warning.main, 0.1)
                            : "transparent",
                        }}
                      >
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {imp.name}
                          </Typography>
                        </TableCell>
                        <TableCell>{imp.library}</TableCell>
                        <TableCell>
                          {imp.is_suspicious ? (
                            <Tooltip title={imp.reason || "Suspicious API"}>
                              <Chip label="⚠️ Suspicious" size="small" color="warning" />
                            </Tooltip>
                          ) : (
                            <Chip label="Normal" size="small" variant="outlined" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Strings */}
      <Accordion expanded={stringsExpanded} onChange={() => setStringsExpanded(!stringsExpanded)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="primary" /> Extracted Strings ({result.strings_count} total, showing {result.strings_sample.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Box sx={{ maxHeight: 400, overflow: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={100}>Offset</TableCell>
                  <TableCell width={100}>Category</TableCell>
                  <TableCell>Value</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.strings_sample.map((str, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        0x{str.offset.toString(16)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={str.category || "general"}
                        size="small"
                        variant="outlined"
                        color={
                          str.category === "url"
                            ? "info"
                            : str.category === "path"
                            ? "secondary"
                            : str.category === "email"
                            ? "warning"
                            : "default"
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontFamily="monospace"
                        sx={{ wordBreak: "break-all" }}
                      >
                        {str.value}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>
        </AccordionDetails>
      </Accordion>

      {/* ELF Security Features */}
      {result.metadata.file_type?.includes("ELF") && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="info" /> ELF Security Features
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.nx_enabled ? "NX Enabled" : "NX Disabled"}
                  color={result.metadata.nx_enabled ? "success" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  No-Execute Stack
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.pie_enabled ? "PIE Enabled" : "No PIE"}
                  color={result.metadata.pie_enabled ? "success" : "warning"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  Position Independent
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.stack_canary ? "Canary Enabled" : "No Canary"}
                  color={result.metadata.stack_canary ? "success" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  Stack Protection
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: "center", p: 1 }}>
                <Chip
                  label={result.metadata.relro || "No RELRO"}
                  color={result.metadata.relro === "Full" ? "success" : result.metadata.relro === "Partial" ? "warning" : "error"}
                  variant="outlined"
                />
                <Typography variant="caption" display="block" sx={{ mt: 0.5 }}>
                  RELRO Protection
                </Typography>
              </Box>
            </Grid>
            {result.metadata.interpreter && (
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Interpreter</Typography>
                <Typography variant="body2" fontFamily="monospace">{result.metadata.interpreter}</Typography>
              </Grid>
            )}
            {result.metadata.linked_libraries && result.metadata.linked_libraries.length > 0 && (
              <Grid item xs={12}>
                <Typography variant="caption" color="text.secondary">Linked Libraries</Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                  {result.metadata.linked_libraries.map((lib, idx) => (
                    <Chip key={idx} label={lib} size="small" variant="outlined" />
                  ))}
                </Box>
              </Grid>
            )}
          </Grid>
        </Paper>
      )}

      {/* PE Rich Header & Imphash - Compiler/Linker Info */}
      {result.metadata.file_type?.includes("PE") && (result.metadata.rich_header || result.metadata.imphash) && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="info" /> PE Rich Header & Build Info
          </Typography>
          
          {/* Imphash and Rich Hash */}
          <Grid container spacing={2} sx={{ mb: 2 }}>
            {result.metadata.imphash && (
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Import Hash (imphash)</Typography>
                <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                  {result.metadata.imphash}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Use for malware family identification
                </Typography>
              </Grid>
            )}
            {result.metadata.rich_header && (
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" color="text.secondary">Rich Header Hash</Typography>
                <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                  {result.metadata.rich_header.rich_hash}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Checksum: 0x{result.metadata.rich_header.checksum.toString(16).toUpperCase()}
                </Typography>
              </Grid>
            )}
          </Grid>

          {/* Rich Header Entries - Compiler/Linker Table */}
          {result.metadata.rich_header && result.metadata.rich_header.entries.length > 0 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>
                Build Tools ({result.metadata.rich_header.entries.length} components)
              </Typography>
              <TableContainer sx={{ maxHeight: 300 }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow>
                      <TableCell>Product</TableCell>
                      <TableCell>Product ID</TableCell>
                      <TableCell>Build ID</TableCell>
                      <TableCell>Count</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.metadata.rich_header.entries.map((entry, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Typography variant="body2">
                            {entry.product_name || `Unknown (${entry.product_id})`}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {entry.product_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {entry.build_id}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {entry.count}
                          </Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </Paper>
      )}

      {/* ELF Symbols */}
      {result.symbols && result.symbols.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <FunctionIcon color="secondary" /> ELF Symbols ({result.symbols.length})
              {result.symbols.filter(s => s.is_suspicious).length > 0 && (
                <Chip
                  label={`${result.symbols.filter(s => s.is_suspicious).length} suspicious`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small" stickyHeader>
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Address</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Binding</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.symbols
                    .sort((a, b) => (b.is_suspicious ? 1 : 0) - (a.is_suspicious ? 1 : 0))
                    .slice(0, 100)
                    .map((sym, idx) => (
                      <TableRow
                        key={idx}
                        sx={{
                          bgcolor: sym.is_suspicious
                            ? alpha(theme.palette.warning.main, 0.1)
                            : sym.is_imported
                            ? alpha(theme.palette.info.main, 0.05)
                            : "transparent",
                        }}
                      >
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {sym.name}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            0x{sym.address.toString(16)}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Chip label={sym.symbol_type} size="small" variant="outlined" />
                        </TableCell>
                        <TableCell>{sym.binding}</TableCell>
                        <TableCell>
                          {sym.is_suspicious ? (
                            <Tooltip title={sym.reason || "Suspicious function"}>
                              <Chip label="⚠️ Suspicious" size="small" color="warning" />
                            </Tooltip>
                          ) : sym.is_imported ? (
                            <Chip label="Imported" size="small" color="info" variant="outlined" />
                          ) : sym.is_exported ? (
                            <Chip label="Exported" size="small" color="success" variant="outlined" />
                          ) : (
                            <Chip label="Local" size="small" variant="outlined" />
                          )}
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Disassembly */}
      {result.disassembly && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="error" /> Disassembly ({result.disassembly.architecture} {result.disassembly.mode})
              {result.disassembly.suspicious_instructions.length > 0 && (
                <Chip
                  label={`${result.disassembly.suspicious_instructions.length} suspicious patterns`}
                  size="small"
                  color="error"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {/* Entry Point Disassembly */}
            {result.disassembly.entry_point_disasm.length > 0 && (
              <Box sx={{ mb: 3 }}>
                <Typography variant="subtitle2" gutterBottom>Entry Point</Typography>
                <Box
                  sx={{
                    bgcolor: "grey.900",
                    color: "grey.100",
                    p: 2,
                    borderRadius: 1,
                    fontFamily: "monospace",
                    fontSize: "0.8rem",
                    maxHeight: 300,
                    overflow: "auto",
                  }}
                >
                  {result.disassembly.entry_point_disasm.map((insn, idx) => (
                    <Box
                      key={idx}
                      sx={{
                        display: "flex",
                        gap: 2,
                        py: 0.25,
                        bgcolor: insn.is_suspicious ? alpha("#ff5722", 0.3) : "transparent",
                        "&:hover": { bgcolor: alpha("#fff", 0.05) },
                      }}
                    >
                      <Typography component="span" sx={{ color: "info.main", minWidth: 100 }}>
                        0x{insn.address.toString(16).padStart(8, "0")}
                      </Typography>
                      <Typography component="span" sx={{ color: "grey.500", minWidth: 80 }}>
                        {insn.bytes_hex}
                      </Typography>
                      <Typography
                        component="span"
                        sx={{
                          color: insn.is_call ? "success.main" : insn.is_jump ? "warning.main" : "grey.100",
                          minWidth: 60,
                        }}
                      >
                        {insn.mnemonic}
                      </Typography>
                      <Typography component="span" sx={{ color: "grey.300" }}>
                        {insn.op_str}
                      </Typography>
                      {insn.comment && (
                        <Typography component="span" sx={{ color: "error.main", ml: "auto" }}>
                          ; {insn.comment}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Box>
              </Box>
            )}

            {/* Function Disassembly */}
            {result.disassembly.functions.length > 0 && (
              <Box>
                <Typography variant="subtitle2" gutterBottom>
                  Analyzed Functions ({result.disassembly.functions.length})
                </Typography>
                {result.disassembly.functions.map((func, fIdx) => (
                  <Accordion key={fIdx} sx={{ mb: 1 }}>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography sx={{ fontFamily: "monospace", display: "flex", alignItems: "center", gap: 1 }}>
                        {func.name}
                        <Typography component="span" variant="caption" color="text.secondary">
                          @ 0x{func.address.toString(16)} ({func.size} bytes)
                        </Typography>
                        {func.suspicious_patterns.length > 0 && (
                          <Chip label="⚠️" size="small" color="warning" />
                        )}
                      </Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      {func.calls.length > 0 && (
                        <Box sx={{ mb: 2 }}>
                          <Typography variant="caption" color="text.secondary">Calls:</Typography>
                          <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                            {func.calls.map((call, cIdx) => (
                              <Chip key={cIdx} label={call} size="small" variant="outlined" />
                            ))}
                          </Box>
                        </Box>
                      )}
                      <Box
                        sx={{
                          bgcolor: "grey.900",
                          color: "grey.100",
                          p: 1,
                          borderRadius: 1,
                          fontFamily: "monospace",
                          fontSize: "0.75rem",
                          maxHeight: 200,
                          overflow: "auto",
                        }}
                      >
                        {func.instructions.slice(0, 50).map((insn, iIdx) => (
                          <Box key={iIdx} sx={{ display: "flex", gap: 1, py: 0.125 }}>
                            <Typography component="span" sx={{ color: "info.main", minWidth: 80, fontSize: "inherit" }}>
                              0x{insn.address.toString(16).padStart(8, "0")}
                            </Typography>
                            <Typography component="span" sx={{ color: insn.is_call ? "success.main" : "grey.100", minWidth: 50, fontSize: "inherit" }}>
                              {insn.mnemonic}
                            </Typography>
                            <Typography component="span" sx={{ color: "grey.400", fontSize: "inherit" }}>
                              {insn.op_str}
                            </Typography>
                          </Box>
                        ))}
                      </Box>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>
            )}
          </AccordionDetails>
        </Accordion>
      )}

      {/* DWARF Debug Info */}
      {result.dwarf_info?.has_debug_info && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="success" /> Debug Information (DWARF)
          </Typography>
          {result.dwarf_info.compilation_units && result.dwarf_info.compilation_units.length > 0 && (
            <Box>
              <Typography variant="subtitle2" gutterBottom>Compilation Units</Typography>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Source File</TableCell>
                      <TableCell>Compiler</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.dwarf_info.compilation_units.map((cu, idx) => (
                      <TableRow key={idx}>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">{cu.name}</Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" sx={{ fontSize: "0.75rem" }}>{cu.producer || "Unknown"}</Typography>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </Paper>
      )}

      {/* AI Analysis */}
      {result.ai_analysis && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="info" /> AI Analysis
          </Typography>
          <Typography
            variant="body2"
            component="pre"
            sx={{
              whiteSpace: "pre-wrap",
              fontFamily: "inherit",
              m: 0,
            }}
          >
            {result.ai_analysis}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

// APK Analysis Results Component
function ApkResults({ 
  result, 
  jadxResult,
  apkFile 
}: { 
  result: ApkAnalysisResult; 
  jadxResult?: JadxDecompilationResult | null;
  apkFile: File | null;
}) {
  const theme = useTheme();

  return (
    <Box>
      {/* App Info */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <ApkIcon color="success" /> APK Information
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="caption" color="text.secondary">Package Name</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.package_name}</Typography>
          </Grid>
          {result.app_name && (
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">App Name</Typography>
              <Typography variant="body1">{result.app_name}</Typography>
            </Grid>
          )}
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Version</Typography>
            <Typography variant="body1">{result.version_name} ({result.version_code})</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Target SDK</Typography>
            <Typography variant="body1">API {result.target_sdk}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Min SDK</Typography>
            <Typography variant="body1">API {result.min_sdk}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Strings Found</Typography>
            <Typography variant="body1">{result.strings_count.toLocaleString()}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Debuggable</Typography>
            <Chip 
              label={result.debuggable ? "Yes" : "No"} 
              size="small" 
              color={result.debuggable ? "error" : "success"}
            />
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Allow Backup</Typography>
            <Chip 
              label={result.allow_backup ? "Yes" : "No"} 
              size="small" 
              color={result.allow_backup ? "warning" : "success"}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* AI Quick Summary - Two tabs */}
      <ApkQuickAISummary result={result} />

      {/* Certificate Info */}
      {result.certificate && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(
          result.certificate.is_debug_cert || result.certificate.is_expired 
            ? theme.palette.error.main 
            : theme.palette.success.main, 0.05
        )}}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LockIcon color={result.certificate.is_debug_cert ? "error" : "success"} /> 
            Signing Certificate
            {result.certificate.is_debug_cert && (
              <Chip label="DEBUG" size="small" color="error" />
            )}
            {result.certificate.is_expired && (
              <Chip label="EXPIRED" size="small" color="error" />
            )}
            <Chip 
              label={`${result.certificate.signature_version} signature`} 
              size="small" 
              color={result.certificate.signature_version === "v1" ? "warning" : "success"}
              variant="outlined"
            />
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Subject</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                {result.certificate.subject}
              </Typography>
            </Grid>
            <Grid item xs={12} sm={6}>
              <Typography variant="caption" color="text.secondary">Issuer</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                {result.certificate.issuer}
              </Typography>
            </Grid>
            <Grid item xs={12}>
              <Typography variant="caption" color="text.secondary">SHA-256 Fingerprint</Typography>
              <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all", fontSize: "0.75rem" }}>
                {result.certificate.fingerprint_sha256}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Valid From</Typography>
              <Typography variant="body2">{result.certificate.valid_from}</Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Valid Until</Typography>
              <Typography variant="body2" color={result.certificate.is_expired ? "error" : "inherit"}>
                {result.certificate.valid_until}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Public Key</Typography>
              <Typography variant="body2">
                {result.certificate.public_key_algorithm} {result.certificate.public_key_bits && `(${result.certificate.public_key_bits} bits)`}
              </Typography>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Self-Signed</Typography>
              <Typography variant="body2">{result.certificate.is_self_signed ? "Yes" : "No"}</Typography>
            </Grid>
          </Grid>
        </Paper>
      )}

      {/* Security Issues */}
      {result.security_issues.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="error" /> Security Issues ({result.security_issues.length})
          </Typography>
          <List dense>
            {result.security_issues.map((issue, idx) => (
              <ListItem key={idx} sx={{ flexDirection: "column", alignItems: "flex-start" }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%", mb: 0.5 }}>
                  <Chip
                    label={issue.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                      color: getSeverityColor(issue.severity),
                      fontWeight: 600,
                      minWidth: 70,
                    }}
                  />
                  <Chip
                    label={issue.category}
                    size="small"
                    variant="outlined"
                    sx={{ fontSize: "0.7rem" }}
                  />
                </Box>
                <Typography variant="body2" sx={{ ml: 0 }}>
                  {issue.description}
                </Typography>
                {issue.recommendation && (
                  <Typography variant="caption" color="text.secondary" sx={{ ml: 0, mt: 0.5 }}>
                    💡 {issue.recommendation}
                  </Typography>
                )}
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Permissions */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <LockIcon color="warning" /> Permissions ({result.permissions.length})
          {result.dangerous_permissions_count > 0 && (
            <Chip
              label={`${result.dangerous_permissions_count} dangerous`}
              size="small"
              color="error"
            />
          )}
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
          {result.permissions
            .sort((a, b) => (b.is_dangerous ? 1 : 0) - (a.is_dangerous ? 1 : 0))
            .map((perm, idx) => (
              <Tooltip key={idx} title={perm.description || perm.name}>
                <Chip
                  label={perm.name.replace("android.permission.", "")}
                  size="small"
                  color={perm.is_dangerous ? "error" : "default"}
                  variant={perm.is_dangerous ? "filled" : "outlined"}
                />
              </Tooltip>
            ))}
        </Box>
      </Paper>

      {/* Secrets */}
      {result.secrets.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecretIcon color="error" /> Hardcoded Secrets ({result.secrets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Severity</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.secrets.map((secret, idx) => (
                  <TableRow key={idx}>
                    <TableCell>{secret.type}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                        {secret.masked_value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={secret.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                          color: getSeverityColor(secret.severity),
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* URLs */}
      {result.urls.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SearchIcon color="primary" /> URLs Found ({result.urls.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ maxHeight: 300, overflow: "auto" }}>
              {result.urls.map((url, idx) => (
                <Typography
                  key={idx}
                  variant="body2"
                  fontFamily="monospace"
                  sx={{ mb: 0.5, wordBreak: "break-all" }}
                >
                  {url}
                </Typography>
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Components */}
      {result.components.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LayersIcon color="primary" /> App Components ({result.components.length})
              {result.components.filter(c => c.is_exported).length > 0 && (
                <Chip
                  label={`${result.components.filter(c => c.is_exported).length} exported`}
                  size="small"
                  color="warning"
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <TableContainer sx={{ maxHeight: 400 }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Name</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Exported</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {result.components.map((comp, idx) => (
                    <TableRow key={idx}>
                      <TableCell>
                        <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                          {comp.name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip label={comp.component_type} size="small" variant="outlined" />
                      </TableCell>
                      <TableCell>
                        {comp.is_exported ? (
                          <Chip label="Exported" size="small" color="warning" />
                        ) : (
                          <Chip label="Internal" size="small" variant="outlined" />
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Native Libraries */}
      {result.native_libraries.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <BinaryIcon color="primary" /> Native Libraries ({result.native_libraries.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
              {result.native_libraries.map((lib, idx) => (
                <Chip key={idx} label={lib} size="small" variant="outlined" />
              ))}
            </Box>
          </AccordionDetails>
        </Accordion>
      )}

      {/* DEX Analysis */}
      {result.dex_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="primary" /> DEX Analysis
              <Chip label={`${result.dex_analysis.total_classes} classes`} size="small" variant="outlined" />
              <Chip label={`${result.dex_analysis.total_methods} methods`} size="small" variant="outlined" />
              {result.dex_analysis.detected_trackers?.length > 0 && (
                <Chip 
                  label={`${result.dex_analysis.detected_trackers.length} trackers`} 
                  size="small" 
                  color="warning" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Detected Trackers */}
              {result.dex_analysis.detected_trackers?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🔍 Detected Trackers/SDKs
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mb: 2 }}>
                    {result.dex_analysis.detected_trackers.map((tracker, idx) => (
                      <Tooltip key={idx} title={tracker.package}>
                        <Chip label={tracker.name} size="small" color="warning" />
                      </Tooltip>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Suspicious Patterns */}
              {result.dex_analysis.reflection_usage?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🔄 Reflection Usage ({result.dex_analysis.reflection_usage.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.reflection_usage.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.class.split('.').pop()}.{item.method}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.crypto_usage?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🔐 Crypto Usage ({result.dex_analysis.crypto_usage.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.crypto_usage.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.pattern}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.native_calls?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚙️ Native Calls ({result.dex_analysis.native_calls.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.native_calls.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.class.split('.').pop()}.{item.method}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.dynamic_loading?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Dynamic Loading ({result.dex_analysis.dynamic_loading.length})
                  </Typography>
                  <Box sx={{ maxHeight: 150, overflow: "auto" }}>
                    {result.dex_analysis.dynamic_loading.slice(0, 10).map((item, idx) => (
                      <Typography key={idx} variant="caption" display="block" fontFamily="monospace">
                        {item.pattern}
                      </Typography>
                    ))}
                  </Box>
                </Grid>
              )}
              
              {result.dex_analysis.anti_analysis_detected?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🛡️ Anti-Analysis Techniques ({result.dex_analysis.anti_analysis_detected.length})
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.dex_analysis.anti_analysis_detected.map((item, idx) => (
                      <Chip key={idx} label={item.pattern} size="small" color="warning" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Resource Analysis */}
      {result.resource_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <StorageIcon color="primary" /> Resources
              <Chip label={`${result.resource_analysis.string_count || 0} strings`} size="small" variant="outlined" />
              <Chip label={`${result.resource_analysis.asset_files?.length || 0} assets`} size="small" variant="outlined" />
              {result.resource_analysis.potential_secrets?.length > 0 && (
                <Chip 
                  label={`${result.resource_analysis.potential_secrets.length} secrets`} 
                  size="small" 
                  color="error" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Resource Stats */}
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Drawables</Typography>
                <Typography variant="body1">{result.resource_analysis.drawable_count || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Layouts</Typography>
                <Typography variant="body1">{result.resource_analysis.layout_count || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Raw Resources</Typography>
                <Typography variant="body1">{result.resource_analysis.raw_resources?.length || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Config Files</Typography>
                <Typography variant="body1">{result.resource_analysis.config_files?.length || 0}</Typography>
              </Grid>
              
              {/* Secrets in Resources */}
              {result.resource_analysis.potential_secrets?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Potential Secrets in Resources
                  </Typography>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Type</TableCell>
                          <TableCell>Source</TableCell>
                          <TableCell>Preview</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.resource_analysis.potential_secrets.slice(0, 10).map((secret, idx) => (
                          <TableRow key={idx}>
                            <TableCell>
                              <Chip label={secret.type} size="small" color="error" variant="outlined" />
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {secret.source}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {secret.value_preview}
                              </Typography>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
              
              {/* Database Files */}
              {result.resource_analysis.database_files?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    🗄️ Database Files
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.resource_analysis.database_files.map((file, idx) => (
                      <Chip key={idx} label={file} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Config Files */}
              {result.resource_analysis.config_files?.length > 0 && (
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>
                    ⚙️ Config Files
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.resource_analysis.config_files.map((file, idx) => (
                      <Chip key={idx} label={file} size="small" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Intent Filter / Deep Link Analysis */}
      {result.intent_filter_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LinkIcon color="primary" /> Deep Links & Intent Filters
              {result.intent_filter_analysis.deep_links?.length > 0 && (
                <Chip 
                  label={`${result.intent_filter_analysis.deep_links.length} deep links`} 
                  size="small" 
                  color="info" 
                />
              )}
              {result.intent_filter_analysis.attack_surface_summary?.custom_uri_schemes?.length > 0 && (
                <Chip 
                  label={`${result.intent_filter_analysis.attack_surface_summary.custom_uri_schemes.length} custom schemes`} 
                  size="small" 
                  color="warning" 
                />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Attack Surface Summary */}
              {result.intent_filter_analysis.attack_surface_summary && (
                <Grid item xs={12}>
                  <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
                    <Typography variant="subtitle2" gutterBottom>Attack Surface Summary</Typography>
                    <Grid container spacing={1}>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Deep Links</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.total_deep_links}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Browsable</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.browsable_activities_count}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Activities</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_activities}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Services</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_services}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Receivers</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_receivers}</Typography>
                      </Grid>
                      <Grid item xs={6} sm={2}>
                        <Typography variant="caption" color="text.secondary">Exp. Providers</Typography>
                        <Typography variant="body2">{result.intent_filter_analysis.attack_surface_summary.exported_providers}</Typography>
                      </Grid>
                    </Grid>
                  </Paper>
                </Grid>
              )}
              
              {/* Custom URI Schemes */}
              {result.intent_filter_analysis.attack_surface_summary?.custom_uri_schemes?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🔗 Custom URI Schemes
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.intent_filter_analysis.attack_surface_summary.custom_uri_schemes.map((scheme, idx) => (
                      <Chip key={idx} label={`${scheme}://`} size="small" color="warning" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Deep Links */}
              {result.intent_filter_analysis.deep_links?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>
                    🌐 Deep Links
                  </Typography>
                  <TableContainer sx={{ maxHeight: 200 }}>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>URL</TableCell>
                          <TableCell>Component</TableCell>
                          <TableCell>Type</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.intent_filter_analysis.deep_links.slice(0, 20).map((link, idx) => (
                          <TableRow key={idx}>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {link.url}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Typography variant="caption" fontFamily="monospace">
                                {link.component.split('.').pop()}
                              </Typography>
                            </TableCell>
                            <TableCell>
                              <Chip label={link.type} size="small" variant="outlined" />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Network Security Config */}
      {result.network_config_analysis && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <SecurityIcon color="primary" /> Network Security Config
              {result.network_config_analysis.has_config ? (
                <Chip label="Configured" size="small" color="success" />
              ) : (
                <Chip label="Not Found" size="small" color="warning" />
              )}
              {result.network_config_analysis.cleartext_permitted && (
                <Chip label="Cleartext Allowed" size="small" color="error" />
              )}
              {result.network_config_analysis.certificate_pins?.length > 0 && (
                <Chip label="Pinning Enabled" size="small" color="success" />
              )}
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Grid container spacing={2}>
              {/* Config Status */}
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Has Config</Typography>
                <Typography variant="body2">{result.network_config_analysis.has_config ? "Yes" : "No"}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Cleartext Default</Typography>
                <Typography variant="body2" color={result.network_config_analysis.cleartext_permitted ? "error.main" : "success.main"}>
                  {result.network_config_analysis.cleartext_permitted ? "Allowed" : "Blocked"}
                </Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Trust Anchors</Typography>
                <Typography variant="body2">{result.network_config_analysis.trust_anchors?.length || 0}</Typography>
              </Grid>
              <Grid item xs={6} sm={3}>
                <Typography variant="caption" color="text.secondary">Pin Sets</Typography>
                <Typography variant="body2">{result.network_config_analysis.certificate_pins?.length || 0}</Typography>
              </Grid>
              
              {/* Security Issues */}
              {result.network_config_analysis.security_issues?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="error.main">
                    ⚠️ Network Security Issues
                  </Typography>
                  <List dense>
                    {result.network_config_analysis.security_issues.map((issue, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <WarningIcon color="error" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText primary={issue} />
                      </ListItem>
                    ))}
                  </List>
                </Grid>
              )}
              
              {/* Cleartext Domains */}
              {result.network_config_analysis.cleartext_domains?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="warning.main">
                    🌐 Cleartext (HTTP) Allowed Domains
                  </Typography>
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                    {result.network_config_analysis.cleartext_domains.map((domain, idx) => (
                      <Chip key={idx} label={domain} size="small" color="warning" variant="outlined" />
                    ))}
                  </Box>
                </Grid>
              )}
              
              {/* Certificate Pins */}
              {result.network_config_analysis.certificate_pins?.length > 0 && (
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom color="success.main">
                    📌 Certificate Pinning
                  </Typography>
                  {result.network_config_analysis.certificate_pins.map((pinSet, idx) => (
                    <Paper key={idx} sx={{ p: 1.5, mb: 1, bgcolor: alpha(theme.palette.success.main, 0.05) }}>
                      <Typography variant="caption" color="text.secondary">
                        Domains: {pinSet.domains?.join(", ")}
                      </Typography>
                      {pinSet.expiration && (
                        <Typography variant="caption" display="block" color="text.secondary">
                          Expires: {pinSet.expiration}
                        </Typography>
                      )}
                      <Typography variant="caption" display="block">
                        {pinSet.pins?.length || 0} pin(s) configured
                      </Typography>
                    </Paper>
                  ))}
                </Grid>
              )}
            </Grid>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Smali/Bytecode Decompilation */}
      {result.smali_analysis && (
        <SmaliViewer smali={result.smali_analysis} />
      )}

      {/* Dynamic Analysis / Frida Scripts */}
      {result.dynamic_analysis && (
        <FridaScriptsViewer dynamicAnalysis={result.dynamic_analysis} />
      )}

      {/* Native Library Analysis */}
      {result.native_analysis && result.native_analysis.total_libraries > 0 && (
        <NativeLibraryViewer nativeAnalysis={result.native_analysis} />
      )}

      {/* Data Flow / Taint Analysis */}
      {result.data_flow_analysis && (
        <DataFlowAnalysisViewer dataFlowAnalysis={result.data_flow_analysis} />
      )}

      {/* Hardening Score */}
      {result.hardening_score && (
        <HardeningScoreCard hardeningScore={result.hardening_score} />
      )}

      {/* Advanced Analysis Tools - Tabbed interface for better viewing */}
      {apkFile && (
        <AdvancedAnalysisToolsTabs apkFile={apkFile} autoStart={!!result} />
      )}

      {/* AI Analysis Reports */}
      <ApkAIReports result={result} />

      {/* AI-Powered Analysis Tools */}
      <ApkAITools analysisResult={result} jadxResult={jadxResult} />

      {/* Deep Code Analysis CTA - Small inline hint when JADX hasn't been run */}
      {!jadxResult && (
        <Alert 
          id="jadx-decompiler-cta"
          severity="info"
          icon={<CodeIcon />}
          sx={{ mt: 2 }}
          action={
            <Button
              color="inherit"
              size="small"
              startIcon={<CodeIcon />}
              onClick={() => {
                document.getElementById('advanced-apk-analysis')?.scrollIntoView({ behavior: 'smooth' });
              }}
            >
              Decompile with JADX
            </Button>
          }
        >
          <Typography variant="body2">
            <strong>Want deeper analysis?</strong> Use JADX Decompiler below for full source code context.
          </Typography>
        </Alert>
      )}
    </Box>
  );
}

// ============================================================================
// Advanced Analysis Tools Tabs - Full-width tabbed interface
// ============================================================================
interface AdvancedAnalysisToolsTabsProps {
  apkFile: File;
  autoStart: boolean;
}

function AdvancedAnalysisToolsTabs({ apkFile, autoStart }: AdvancedAnalysisToolsTabsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);

  return (
    <Paper sx={{ mt: 3, overflow: 'hidden' }}>
      {/* Header */}
      <Box 
        sx={{ 
          p: 2, 
          background: `linear-gradient(135deg, ${alpha(theme.palette.info.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
          borderBottom: `1px solid ${theme.palette.divider}`
        }}
      >
        <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          🔬 Advanced Analysis Tools
          {autoStart && (
            <Chip 
              label="Auto-Running" 
              size="small" 
              color="success" 
              variant="outlined" 
              sx={{ ml: 1 }} 
            />
          )}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Deep analysis tools that complement the Quick Scan results
        </Typography>
      </Box>

      {/* Tabs */}
      <Tabs 
        value={activeTab} 
        onChange={(_, newValue) => setActiveTab(newValue)}
        variant="fullWidth"
        sx={{
          borderBottom: `1px solid ${theme.palette.divider}`,
          '& .MuiTab-root': {
            py: 2,
            fontWeight: 500,
          }
        }}
      >
        <Tab 
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <span>📋</span>
              <span>Manifest Visualization</span>
            </Box>
          }
        />
        <Tab 
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <span>🎯</span>
              <span>Attack Surface Map</span>
            </Box>
          }
        />
        <Tab 
          label={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <span>🔐</span>
              <span>Obfuscation Analysis</span>
            </Box>
          }
        />
      </Tabs>

      {/* Tab Panels - All components mounted for parallel autoStart, visibility controlled */}
      <Box sx={{ p: 0 }}>
        <Box sx={{ p: 2, display: activeTab === 0 ? 'block' : 'none' }}>
          <ManifestVisualizer apkFile={apkFile} autoStart={autoStart} />
        </Box>
        <Box sx={{ p: 2, display: activeTab === 1 ? 'block' : 'none' }}>
          <AttackSurfaceMap apkFile={apkFile} autoStart={autoStart} />
        </Box>
        <Box sx={{ p: 2, display: activeTab === 2 ? 'block' : 'none' }}>
          <ObfuscationAnalyzer apkFile={apkFile} autoStart={autoStart} />
        </Box>
      </Box>
    </Paper>
  );
}

// ============================================================================
// APK Quick AI Summary Component - "What Does This APK Do?" and "Quick Security Findings"
// ============================================================================
function ApkQuickAISummary({ result }: { result: ApkAnalysisResult }) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [functionalitySummary, setFunctionalitySummary] = useState<string | null>(null);
  const [securitySummary, setSecuritySummary] = useState<string | null>(null);
  const [isLoadingFunc, setIsLoadingFunc] = useState(false);
  const [isLoadingSec, setIsLoadingSec] = useState(false);
  const [errorFunc, setErrorFunc] = useState<string | null>(null);
  const [errorSec, setErrorSec] = useState<string | null>(null);

  // Format markdown to HTML with proper styling
  const formatMarkdownToHtml = (markdown: string): string => {
    if (!markdown) return "";
    
    let html = markdown;
    
    // Headers
    html = html.replace(/^#### (.*$)/gim, '<h4 style="font-size: 1rem; font-weight: 600; margin: 1rem 0 0.5rem 0; color: inherit;">$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 1.1rem; font-weight: 700; margin: 1.25rem 0 0.5rem 0; color: #60a5fa;">$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 1.2rem; font-weight: 700; margin: 1.5rem 0 0.75rem 0; color: inherit;">$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 1.3rem; font-weight: 700; margin: 1.5rem 0 0.75rem 0;">$1</h1>');
    
    // Bold and italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: 600; color: inherit;">$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.3); padding: 0.1rem 0.3rem; border-radius: 0.25rem; font-size: 0.85em; font-family: monospace;">$1</code>');
    
    // Process lines for lists and paragraphs
    const lines = html.split('\n');
    const processedLines: string[] = [];
    let inList = false;
    let listType: 'ul' | 'ol' = 'ul';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const bulletMatch = line.match(/^[\s]*[-*•]\s+(.*)$/);
      const numberedMatch = line.match(/^[\s]*(\d+)\.\s+(.*)$/);
      
      if (bulletMatch) {
        if (!inList || listType !== 'ul') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ul style="margin: 0.5rem 0; padding-left: 1.25rem; list-style-type: disc;">');
          inList = true;
          listType = 'ul';
        }
        processedLines.push(`<li style="margin: 0.35rem 0; line-height: 1.5;">${bulletMatch[1]}</li>`);
      } else if (numberedMatch) {
        if (!inList || listType !== 'ol') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ol style="margin: 0.5rem 0; padding-left: 1.25rem;">');
          inList = true;
          listType = 'ol';
        }
        processedLines.push(`<li style="margin: 0.35rem 0; line-height: 1.5;">${numberedMatch[2]}</li>`);
      } else {
        if (inList) {
          processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          inList = false;
        }
        // Handle paragraphs - skip empty lines, wrap non-empty text
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('<h') && !trimmedLine.startsWith('<pre') && !trimmedLine.startsWith('<ul') && !trimmedLine.startsWith('<ol')) {
          processedLines.push(`<p style="margin: 0.5rem 0; line-height: 1.6;">${line}</p>`);
        } else if (trimmedLine) {
          processedLines.push(line);
        }
      }
    }
    
    if (inList) {
      processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
    }
    
    return processedLines.join('\n');
  };

  // Generate functionality summary
  const generateFunctionalitySummary = async () => {
    if (functionalitySummary) return; // Already generated
    setIsLoadingFunc(true);
    setErrorFunc(null);
    try {
      const request = {
        message: `Based on the APK analysis results, provide a clear summary explaining what this app does.

Use proper markdown formatting with:
- **Bold text** for important terms
- ### Headers for sections
- Bullet points for lists

Structure your response as:

### App Overview
Brief 1-2 sentence description of the app's main purpose.

### Key Features
- Feature 1 based on permissions/components
- Feature 2
- Feature 3

### Target Audience
Who this app is designed for and typical use cases.

Be concise and user-friendly. Focus on what matters most.`,
        conversation_history: [],
        analysis_context: result as unknown as Record<string, unknown>,
        beginner_mode: true,
      };
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setFunctionalitySummary(response.response);
    } catch (err) {
      setErrorFunc(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setIsLoadingFunc(false);
    }
  };

  // Generate security summary
  const generateSecuritySummary = async () => {
    if (securitySummary) return; // Already generated
    setIsLoadingSec(true);
    setErrorSec(null);
    try {
      const request = {
        message: `Based on the APK analysis results, provide a security assessment.

Use proper markdown formatting with:
- **Bold text** for important terms and severity levels
- ### Headers for sections  
- Bullet points for findings

Structure your response as:

### Security Rating
**[Good/Moderate/Concerning]** - Brief 1 sentence explanation.

### Key Security Concerns
- **Issue 1**: Brief description
- **Issue 2**: Brief description
- **Issue 3**: Brief description

### Recommendations
- Recommendation 1
- Recommendation 2

Be direct and actionable. Prioritize the most important issues.`,
        conversation_history: [],
        analysis_context: result as unknown as Record<string, unknown>,
        beginner_mode: true,
      };
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setSecuritySummary(response.response);
    } catch (err) {
      setErrorSec(err instanceof Error ? err.message : "Failed to generate summary");
    } finally {
      setIsLoadingSec(false);
    }
  };

  // Auto-generate on tab switch
  useEffect(() => {
    if (activeTab === 0 && !functionalitySummary && !isLoadingFunc) {
      generateFunctionalitySummary();
    } else if (activeTab === 1 && !securitySummary && !isLoadingSec) {
      generateSecuritySummary();
    }
  }, [activeTab]);

  return (
    <Paper sx={{ p: 0, mb: 3, overflow: "hidden" }}>
      {/* Tabs Header */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.primary.main, 0.03),
      }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          centered
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              px: 4,
              textTransform: "none",
              fontSize: "1rem",
              minHeight: 56,
            },
          }}
        >
          <Tab
            icon={<AiIcon sx={{ fontSize: 22 }} />}
            iconPosition="start"
            label="🤔 What Does This APK Do?"
            sx={{ gap: 1 }}
          />
          <Tab
            icon={<ShieldIcon sx={{ fontSize: 22 }} />}
            iconPosition="start"
            label="🔒 Quick Security Findings"
            sx={{ gap: 1 }}
          />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <Box sx={{ p: 2.5, minHeight: 150 }}>
        {/* Functionality Tab */}
        {activeTab === 0 && (
          <Box>
            {isLoadingFunc ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, py: 3, justifyContent: "center" }}>
                <CircularProgress size={24} />
                <Typography variant="body2" color="text.secondary">
                  Analyzing app functionality...
                </Typography>
              </Box>
            ) : errorFunc ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={generateFunctionalitySummary}>
                    Retry
                  </Button>
                }
              >
                {errorFunc}
              </Alert>
            ) : functionalitySummary ? (
              <Box 
                sx={{ 
                  lineHeight: 1.6,
                  color: theme.palette.text.secondary,
                  '& h1, & h2, & h3, & h4': { color: theme.palette.text.primary },
                  '& strong': { color: theme.palette.text.primary },
                  '& ul, & ol': { marginLeft: 0 },
                  '& p:first-of-type': { marginTop: 0 },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(functionalitySummary) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <Button
                  variant="outlined"
                  startIcon={<AiIcon />}
                  onClick={generateFunctionalitySummary}
                >
                  Generate Summary
                </Button>
              </Box>
            )}
          </Box>
        )}

        {/* Security Tab */}
        {activeTab === 1 && (
          <Box>
            {isLoadingSec ? (
              <Box sx={{ display: "flex", alignItems: "center", gap: 2, py: 3, justifyContent: "center" }}>
                <CircularProgress size={24} />
                <Typography variant="body2" color="text.secondary">
                  Analyzing security posture...
                </Typography>
              </Box>
            ) : errorSec ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={generateSecuritySummary}>
                    Retry
                  </Button>
                }
              >
                {errorSec}
              </Alert>
            ) : securitySummary ? (
              <Box 
                sx={{ 
                  lineHeight: 1.6,
                  color: theme.palette.text.secondary,
                  '& h1, & h2, & h3, & h4': { color: theme.palette.text.primary },
                  '& strong': { color: theme.palette.text.primary },
                  '& ul, & ol': { marginLeft: 0 },
                  '& p:first-of-type': { marginTop: 0 },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(securitySummary) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 2 }}>
                <Button
                  variant="outlined"
                  startIcon={<ShieldIcon />}
                  onClick={generateSecuritySummary}
                >
                  Generate Summary
                </Button>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
}

// ============================================================================
// Deep Analysis Reports Component - Full reports after JADX decompilation
// ============================================================================
interface DeepAnalysisReportsProps {
  jadxResult: JadxDecompilationResult;
  quickScanResult: ApkAnalysisResult;
  // Callbacks to share report data with parent for saving
  onFunctionalityReportGenerated?: (report: string) => void;
  onSecurityReportGenerated?: (report: string) => void;
}

function DeepAnalysisReports({ 
  jadxResult, 
  quickScanResult, 
  onFunctionalityReportGenerated,
  onSecurityReportGenerated
}: DeepAnalysisReportsProps) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [functionalityReport, setFunctionalityReport] = useState<string | null>(null);
  const [securityReport, setSecurityReport] = useState<string | null>(null);
  const [isLoadingFunc, setIsLoadingFunc] = useState(false);
  const [isLoadingSec, setIsLoadingSec] = useState(false);
  const [errorFunc, setErrorFunc] = useState<string | null>(null);
  const [errorSec, setErrorSec] = useState<string | null>(null);
  const [autoGenerated, setAutoGenerated] = useState(false);

  // Format markdown to HTML with proper styling
  const formatMarkdownToHtml = (markdown: string): string => {
    if (!markdown) return "";
    
    let html = markdown;
    
    // Headers
    html = html.replace(/^#### (.*$)/gim, '<h4 style="font-size: 1rem; font-weight: 600; margin: 1.5rem 0 0.75rem 0; color: inherit;">$1</h4>');
    html = html.replace(/^### (.*$)/gim, '<h3 style="font-size: 1.1rem; font-weight: 700; margin: 1.75rem 0 0.75rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 0.5rem;">$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2 style="font-size: 1.25rem; font-weight: 700; margin: 2rem 0 1rem 0; color: inherit;">$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1 style="font-size: 1.5rem; font-weight: 700; margin: 2rem 0 1rem 0;">$1</h1>');
    
    // Bold and italic
    html = html.replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>');
    html = html.replace(/\*\*(.*?)\*\*/g, '<strong style="font-weight: 600;">$1</strong>');
    html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
    
    // Code blocks
    html = html.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
      return `<pre style="background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 0.5rem; overflow-x: auto; margin: 1rem 0; font-size: 0.85rem;"><code>${code.trim()}</code></pre>`;
    });
    
    // Inline code
    html = html.replace(/`([^`]+)`/g, '<code style="background: rgba(0,0,0,0.2); padding: 0.15rem 0.4rem; border-radius: 0.25rem; font-size: 0.9em;">$1</code>');
    
    // Process lines for lists and paragraphs
    const lines = html.split('\n');
    const processedLines: string[] = [];
    let inList = false;
    let listType: 'ul' | 'ol' = 'ul';
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const bulletMatch = line.match(/^[\s]*[-*•]\s+(.*)$/);
      const numberedMatch = line.match(/^[\s]*(\d+)\.\s+(.*)$/);
      
      if (bulletMatch) {
        if (!inList || listType !== 'ul') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ul style="margin: 0.75rem 0; padding-left: 1.5rem;">');
          inList = true;
          listType = 'ul';
        }
        processedLines.push(`<li style="margin: 0.5rem 0; line-height: 1.6;">${bulletMatch[1]}</li>`);
      } else if (numberedMatch) {
        if (!inList || listType !== 'ol') {
          if (inList) processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          processedLines.push('<ol style="margin: 0.75rem 0; padding-left: 1.5rem;">');
          inList = true;
          listType = 'ol';
        }
        processedLines.push(`<li style="margin: 0.5rem 0; line-height: 1.6;">${numberedMatch[2]}</li>`);
      } else {
        if (inList) {
          processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
          inList = false;
        }
        // Wrap non-empty lines that aren't already tags in <p>
        const trimmedLine = line.trim();
        if (trimmedLine && !trimmedLine.startsWith('<')) {
          processedLines.push(`<p style="margin: 0.75rem 0; line-height: 1.7;">${trimmedLine}</p>`);
        } else if (trimmedLine) {
          processedLines.push(line);
        }
      }
    }
    if (inList) {
      processedLines.push(listType === 'ol' ? '</ol>' : '</ul>');
    }
    
    return processedLines.join('\n');
  };

  // Generate comprehensive functionality report
  const generateFunctionalityReport = async () => {
    if (functionalityReport) return;
    setIsLoadingFunc(true);
    setErrorFunc(null);
    
    try {
      // Build context from both JADX and quick scan
      const context = {
        ...quickScanResult,
        jadx_info: {
          total_classes: jadxResult.total_classes,
          total_files: jadxResult.total_files,
          output_directory: jadxResult.output_directory,
          class_list_sample: jadxResult.classes?.slice(0, 50).map(c => c.class_name) || [],
          security_issues_count: jadxResult.security_issues?.length || 0,
        }
      };
      
      const request = {
        message: `You are analyzing a decompiled Android APK. Generate a comprehensive, well-formatted report explaining what this app does.

Use proper markdown formatting with:
- **Bold headers** using ## and ###
- Bullet point lists for features
- Code formatting for technical terms

Structure the report as follows:

## 📱 Application Overview
Brief description of the app's main purpose and target users.

## 🎯 Core Functionality
List the main features and what the app does:
- Feature 1: Description
- Feature 2: Description
- etc.

## 🔧 Technical Architecture
- SDK targets and compatibility
- Key libraries and frameworks used
- Native code components (if any)

## 📡 Network & Communication
- API endpoints and services
- Data synchronization patterns
- Third-party integrations

## 💾 Data Handling
- What data the app collects
- Storage mechanisms used
- Data sharing capabilities

## 🎨 User Experience
- Main UI components and activities
- User workflows and navigation
- Content providers and services

## 📊 Summary
Brief conclusion about the app's purpose and sophistication level.

Be specific and technical but accessible. Reference actual class names, permissions, and components found in the analysis.`,
        conversation_history: [],
        analysis_context: context as unknown as Record<string, unknown>,
        beginner_mode: false,
      };
      
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setFunctionalityReport(response.response);
      // Notify parent component for saving
      onFunctionalityReportGenerated?.(response.response);
    } catch (err) {
      setErrorFunc(err instanceof Error ? err.message : "Failed to generate report");
    } finally {
      setIsLoadingFunc(false);
    }
  };

  // Generate comprehensive security report with exploit scenarios
  const generateSecurityReport = async () => {
    if (securityReport) return;
    setIsLoadingSec(true);
    setErrorSec(null);
    
    try {
      const context = {
        ...quickScanResult,
        jadx_info: {
          total_classes: jadxResult.total_classes,
          total_files: jadxResult.total_files,
          output_directory: jadxResult.output_directory,
          class_list_sample: jadxResult.classes?.slice(0, 50).map(c => c.class_name) || [],
          security_issues_count: jadxResult.security_issues?.length || 0,
        }
      };
      
      const request = {
        message: `You are a security researcher analyzing a decompiled Android APK. Generate a comprehensive security assessment report with exploit scenarios.

Use proper markdown formatting with:
- **Bold headers** using ## and ###  
- Bullet points and numbered lists
- Code blocks for technical details
- Severity indicators (🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low)

Structure the report as follows:

## 🛡️ Executive Summary
Overall security posture rating and key findings summary.

## 🔴 Critical & High Severity Issues
For each critical/high issue found:
### Issue Name
- **Severity:** 🔴 Critical / 🟠 High
- **Location:** Specific class/method
- **Description:** What the vulnerability is
- **Impact:** What could happen if exploited
- **Exploit Scenario:** Step-by-step attack path

## 🟡 Medium Severity Issues
Similar structure for medium issues.

## 🟢 Low Severity & Informational
Brief list of minor issues and hardening recommendations.

## 🎯 Attack Surface Analysis
- Exported components and their risks
- Deep link attack vectors
- Intent handling weaknesses
- Content provider exposure

## 🔐 Cryptographic Assessment
- Encryption methods used
- Key management practices
- Certificate validation
- Weaknesses found

## 📡 Network Security
- SSL/TLS implementation
- Certificate pinning status
- Cleartext traffic risks
- API security concerns

## 💾 Data Storage Security
- Sensitive data storage methods
- SharedPreferences security
- Database encryption
- File permissions

## 🛠️ Exploit Scenarios
Provide 2-3 detailed attack scenarios:

### Scenario 1: [Attack Name]
1. **Preconditions:** What attacker needs
2. **Attack Steps:** Numbered exploitation steps
3. **Tools Required:** Frida, adb, etc.
4. **Expected Outcome:** What attacker gains
5. **Mitigation:** How to fix

## 📋 Prioritized Recommendations
Numbered list of fixes in order of priority.

## 📊 Risk Matrix
Summary table of all findings by severity.

Be specific with class names, methods, and technical details from the decompiled code.`,
        conversation_history: [],
        analysis_context: context as unknown as Record<string, unknown>,
        beginner_mode: false,
      };
      
      const response = await reverseEngineeringClient.chatAboutApk(request);
      setSecurityReport(response.response);
      // Notify parent component for saving
      onSecurityReportGenerated?.(response.response);
    } catch (err) {
      setErrorSec(err instanceof Error ? err.message : "Failed to generate report");
    } finally {
      setIsLoadingSec(false);
    }
  };

  // Auto-generate reports when component mounts
  useEffect(() => {
    if (!autoGenerated) {
      setAutoGenerated(true);
      // Start generating both reports
      generateFunctionalityReport();
      generateSecurityReport();
    }
  }, []);

  // Generate report when tab changes if not already generated
  useEffect(() => {
    if (activeTab === 0 && !functionalityReport && !isLoadingFunc) {
      generateFunctionalityReport();
    } else if (activeTab === 1 && !securityReport && !isLoadingSec) {
      generateSecurityReport();
    }
  }, [activeTab]);

  return (
    <Paper sx={{ mt: 4, overflow: "hidden" }}>
      {/* Header */}
      <Box sx={{ 
        p: 2, 
        background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.15)} 0%, ${alpha(theme.palette.secondary.main, 0.15)} 100%)`,
        borderBottom: `1px solid ${alpha(theme.palette.divider, 0.3)}`,
      }}>
        <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="primary" />
          📊 Deep Analysis Reports
          <Chip 
            label="Source Code Context" 
            size="small" 
            color="success" 
            icon={<CodeIcon />}
            sx={{ ml: 1 }}
          />
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Comprehensive AI-generated reports based on {jadxResult.total_classes.toLocaleString()} decompiled classes
        </Typography>
      </Box>

      {/* Tabs */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.background.paper, 0.5),
      }}>
        <Tabs
          value={activeTab}
          onChange={(_, newValue) => setActiveTab(newValue)}
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              textTransform: "none",
              fontSize: "0.95rem",
            },
          }}
        >
          <Tab
            icon={<ApkIcon sx={{ fontSize: 20 }} />}
            iconPosition="start"
            label="📱 What Does This APK Do (Full Report)"
            sx={{ gap: 0.5 }}
          />
          <Tab
            icon={<ShieldIcon sx={{ fontSize: 20 }} />}
            iconPosition="start"
            label="🔒 Advanced Security & Exploits"
            sx={{ gap: 0.5 }}
          />
        </Tabs>
      </Box>

      {/* Tab Content */}
      <Box sx={{ p: 3, minHeight: 400 }}>
        {/* Functionality Report Tab */}
        {activeTab === 0 && (
          <Box>
            {isLoadingFunc ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 6 }}>
                <CircularProgress size={40} />
                <Typography variant="body1" color="text.secondary">
                  Generating comprehensive functionality report...
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyzing {jadxResult.total_classes.toLocaleString()} classes and {jadxResult.total_files.toLocaleString()} files
                </Typography>
              </Box>
            ) : errorFunc ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={() => { setFunctionalityReport(null); generateFunctionalityReport(); }}>
                    Retry
                  </Button>
                }
              >
                {errorFunc}
              </Alert>
            ) : functionalityReport ? (
              <Box
                sx={{
                  "& h1, & h2, & h3, & h4": { color: theme.palette.text.primary },
                  "& p": { color: theme.palette.text.secondary },
                  "& li": { color: theme.palette.text.secondary },
                  "& code": { color: theme.palette.primary.main, bgcolor: alpha(theme.palette.primary.main, 0.1) },
                  "& pre": { bgcolor: alpha(theme.palette.common.black, 0.2) },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(functionalityReport) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Button
                  variant="contained"
                  startIcon={<AiIcon />}
                  onClick={generateFunctionalityReport}
                  size="large"
                >
                  Generate Full Functionality Report
                </Button>
              </Box>
            )}
          </Box>
        )}

        {/* Security Report Tab */}
        {activeTab === 1 && (
          <Box>
            {isLoadingSec ? (
              <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 2, py: 6 }}>
                <CircularProgress size={40} color="error" />
                <Typography variant="body1" color="text.secondary">
                  Generating advanced security report with exploit scenarios...
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Analyzing attack surface, vulnerabilities, and exploitation paths
                </Typography>
              </Box>
            ) : errorSec ? (
              <Alert 
                severity="error" 
                action={
                  <Button color="inherit" size="small" onClick={() => { setSecurityReport(null); generateSecurityReport(); }}>
                    Retry
                  </Button>
                }
              >
                {errorSec}
              </Alert>
            ) : securityReport ? (
              <Box
                sx={{
                  "& h1, & h2, & h3, & h4": { color: theme.palette.text.primary },
                  "& p": { color: theme.palette.text.secondary },
                  "& li": { color: theme.palette.text.secondary },
                  "& code": { color: theme.palette.error.main, bgcolor: alpha(theme.palette.error.main, 0.1) },
                  "& pre": { bgcolor: alpha(theme.palette.common.black, 0.2) },
                }}
                dangerouslySetInnerHTML={{ __html: formatMarkdownToHtml(securityReport) }}
              />
            ) : (
              <Box sx={{ textAlign: "center", py: 4 }}>
                <Button
                  variant="contained"
                  color="error"
                  startIcon={<ShieldIcon />}
                  onClick={generateSecurityReport}
                  size="large"
                >
                  Generate Security & Exploit Report
                </Button>
              </Box>
            )}
          </Box>
        )}
      </Box>
    </Paper>
  );
}

// ============================================================================
// APK AI Reports Component - Two Formatted Reports with Export
// ============================================================================

// Helper function to convert markdown-like content to HTML
function formatReportContent(content: string): string {
  if (!content) return "";
  
  let html = content;
  
  // If it's already HTML (has HTML tags), just clean it up
  if (html.includes("<h3>") || html.includes("<ul>") || html.includes("<p>")) {
    // Already HTML, just ensure proper formatting
    return html;
  }
  
  // Convert markdown to HTML
  // Headers
  html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^## (.*$)/gim, '<h3>$1</h3>');
  html = html.replace(/^# (.*$)/gim, '<h3>$1</h3>');
  
  // Bold text
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/__(.*?)__/g, '<strong>$1</strong>');
  
  // Italic text
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');
  html = html.replace(/_(.*?)_/g, '<em>$1</em>');
  
  // Code blocks
  html = html.replace(/```[\s\S]*?```/g, (match) => {
    const code = match.replace(/```\w*\n?/g, '').replace(/```/g, '');
    return `<pre><code>${code}</code></pre>`;
  });
  
  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  
  // Convert bullet lists
  const lines = html.split('\n');
  let inList = false;
  const processedLines: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isBullet = /^[\s]*[-*•]\s+(.*)/.test(line);
    const isNumbered = /^[\s]*\d+\.\s+(.*)/.test(line);
    
    if (isBullet || isNumbered) {
      if (!inList) {
        processedLines.push(isBullet ? '<ul>' : '<ol>');
        inList = true;
      }
      const content = line.replace(/^[\s]*[-*•]\s+/, '').replace(/^[\s]*\d+\.\s+/, '');
      processedLines.push(`<li>${content}</li>`);
    } else {
      if (inList) {
        processedLines.push('</ul>');
        inList = false;
      }
      // Wrap non-empty lines that aren't already tags in <p>
      if (line.trim() && !line.trim().startsWith('<')) {
        processedLines.push(`<p>${line}</p>`);
      } else {
        processedLines.push(line);
      }
    }
  }
  if (inList) {
    processedLines.push('</ul>');
  }
  
  return processedLines.join('\n');
}

function ApkAIReports({ result }: { result: ApkAnalysisResult }) {
  const theme = useTheme();
  const [activeReport, setActiveReport] = useState(0);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);

  // Check if we have the new structured reports or diagrams
  const hasStructuredReports = result.ai_report_functionality || result.ai_report_security;
  const hasDiagrams = result.ai_architecture_diagram || result.ai_data_flow_diagram;
  const hasLegacyReport = result.ai_analysis && !hasStructuredReports;

  if (!hasStructuredReports && !hasLegacyReport && !hasDiagrams) {
    return null;
  }

  // Common styles for HTML content - improved for better rendering
  const htmlContentStyles = {
    fontFamily: theme.typography.fontFamily,
    "& h3": {
      fontSize: "1.15rem",
      fontWeight: 700,
      color: theme.palette.text.primary,
      mt: 3,
      mb: 1.5,
      pt: 1,
      borderBottom: `1px solid ${alpha(theme.palette.divider, 0.5)}`,
      pb: 1,
      display: "flex",
      alignItems: "center",
      gap: 1,
    },
    "& h3:first-of-type": {
      mt: 0,
      pt: 0,
    },
    "& h4": {
      fontSize: "1rem",
      fontWeight: 600,
      color: theme.palette.text.primary,
      mt: 2,
      mb: 1,
    },
    "& p": {
      mb: 1.5,
      lineHeight: 1.8,
      color: theme.palette.text.secondary,
      fontSize: "0.95rem",
    },
    "& ul, & ol": {
      pl: 3,
      mb: 2,
      mt: 1,
    },
    "& li": {
      mb: 1,
      lineHeight: 1.7,
      color: theme.palette.text.secondary,
      fontSize: "0.95rem",
      "& strong": {
        color: theme.palette.text.primary,
        fontWeight: 600,
      },
    },
    "& strong": {
      fontWeight: 600,
      color: theme.palette.text.primary,
    },
    "& em": {
      fontStyle: "italic",
    },
    "& code": {
      bgcolor: alpha(theme.palette.primary.main, 0.08),
      color: theme.palette.primary.main,
      px: 0.75,
      py: 0.25,
      borderRadius: 0.5,
      fontFamily: "monospace",
      fontSize: "0.85em",
    },
    "& pre": {
      bgcolor: alpha(theme.palette.grey[900], 0.05),
      p: 2,
      borderRadius: 1,
      overflow: "auto",
      "& code": {
        bgcolor: "transparent",
        p: 0,
      },
    },
    "& span[style*='color: #dc2626']": {
      bgcolor: alpha("#dc2626", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #ea580c']": {
      bgcolor: alpha("#ea580c", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #ca8a04']": {
      bgcolor: alpha("#ca8a04", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
    "& span[style*='color: #16a34a']": {
      bgcolor: alpha("#16a34a", 0.1),
      px: 1,
      py: 0.25,
      borderRadius: 0.5,
    },
  };

  // Export handler for current report
  const handleExport = async (format: "markdown" | "pdf" | "docx") => {
    setExportMenuAnchor(null);
    setExporting(true);
    setExportError(null);
    setExportSuccess(null);
    
    try {
      // Determine which report type to export based on active tab
      const reportType = activeReport === 0 ? "functionality" : activeReport === 1 ? "security" : "both";
      
      const blob = await reverseEngineeringClient.exportApkReportFromResult(result, format, reportType);
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const packageName = result.package_name?.split(".").pop() || "apk";
      const reportSuffix = reportType === "both" ? "" : `_${reportType}`;
      a.download = `${packageName}${reportSuffix}_report.${format === "docx" ? "docx" : format === "pdf" ? "pdf" : "md"}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportSuccess(`Report exported as ${format.toUpperCase()}`);
      setTimeout(() => setExportSuccess(null), 3000);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  // Export handler for both reports combined
  const handleExportBoth = async (format: "markdown" | "pdf" | "docx") => {
    setExportMenuAnchor(null);
    setExporting(true);
    setExportError(null);
    setExportSuccess(null);
    
    try {
      const blob = await reverseEngineeringClient.exportApkReportFromResult(result, format, "both");
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const packageName = result.package_name?.split(".").pop() || "apk";
      a.download = `${packageName}_full_report.${format === "docx" ? "docx" : format === "pdf" ? "pdf" : "md"}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      
      setExportSuccess(`Full report exported as ${format.toUpperCase()}`);
      setTimeout(() => setExportSuccess(null), 3000);
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
      // Reset to first tab
      setActiveReport(0);
    }
  };

  // Legacy report display (plain text)
  if (hasLegacyReport) {
    return (
      <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="info" /> AI Analysis
        </Typography>
        <Typography
          variant="body2"
          component="pre"
          sx={{
            whiteSpace: "pre-wrap",
            fontFamily: "inherit",
            m: 0,
          }}
        >
          {result.ai_analysis}
        </Typography>
      </Paper>
    );
  }

  // New structured reports with tabs
  return (
    <Paper sx={{ mt: 3, overflow: "hidden" }}>
      {/* Tabs Header with Export Button */}
      <Box sx={{ 
        borderBottom: 1, 
        borderColor: "divider",
        bgcolor: alpha(theme.palette.primary.main, 0.03),
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        pr: 2,
      }}>
        <Tabs
          value={activeReport}
          onChange={(_, newValue) => setActiveReport(newValue)}
          sx={{
            "& .MuiTab-root": {
              fontWeight: 600,
              py: 2,
              textTransform: "none",
              fontSize: "0.95rem",
            },
          }}
        >
          <Tab
            icon={<ApkIcon />}
            iconPosition="start"
            label="📱 What Does This APK Do"
            sx={{ gap: 1 }}
          />
          <Tab
            icon={<ShieldIcon />}
            iconPosition="start"
            label="🔒 Security Findings"
            sx={{ gap: 1 }}
          />
          {hasDiagrams && (
            <Tab
              icon={<LayersIcon />}
              iconPosition="start"
              label="🕸️ Architecture Diagram"
              sx={{ gap: 1 }}
            />
          )}
          {result.ai_data_flow_diagram && (
            <Tab
              icon={<LinkIcon />}
              iconPosition="start"
              label="🔄 Data Flow Diagram"
              sx={{ gap: 1 }}
            />
          )}
        </Tabs>
        
        {/* Export Button */}
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          {exporting && <CircularProgress size={20} />}
          <Button
            variant="outlined"
            size="small"
            startIcon={<DownloadIcon />}
            onClick={(e) => setExportMenuAnchor(e.currentTarget)}
            disabled={exporting}
            sx={{ textTransform: "none" }}
          >
            Export Report
          </Button>
          <Menu
            anchorEl={exportMenuAnchor}
            open={Boolean(exportMenuAnchor)}
            onClose={() => setExportMenuAnchor(null)}
          >
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: "text.secondary", display: "block" }}>
              Export Current Report
            </Typography>
            <MenuItem onClick={() => handleExport("markdown")}>
              <ListItemIcon>
                <CodeIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Markdown (.md)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExport("pdf")}>
              <ListItemIcon>
                <PdfIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>PDF (.pdf)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExport("docx")}>
              <ListItemIcon>
                <DocIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Word (.docx)</ListItemText>
            </MenuItem>
            <Divider sx={{ my: 1 }} />
            <Typography variant="caption" sx={{ px: 2, py: 0.5, color: "text.secondary", display: "block" }}>
              Export Both Reports
            </Typography>
            <MenuItem onClick={() => handleExportBoth("markdown")}>
              <ListItemIcon>
                <CodeIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as Markdown (.md)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExportBoth("pdf")}>
              <ListItemIcon>
                <PdfIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as PDF (.pdf)</ListItemText>
            </MenuItem>
            <MenuItem onClick={() => handleExportBoth("docx")}>
              <ListItemIcon>
                <DocIcon fontSize="small" />
              </ListItemIcon>
              <ListItemText>Both as Word (.docx)</ListItemText>
            </MenuItem>
          </Menu>
        </Box>
      </Box>

      {/* Success/Error Messages */}
      {exportSuccess && (
        <Alert severity="success" sx={{ m: 2 }} onClose={() => setExportSuccess(null)}>
          {exportSuccess}
        </Alert>
      )}
      {exportError && (
        <Alert severity="error" sx={{ m: 2 }} onClose={() => setExportError(null)}>
          {exportError}
        </Alert>
      )}

      {/* Report Content */}
      <Box sx={{ p: 3 }}>
        {/* Functionality Report */}
        {activeReport === 0 && result.ai_report_functionality && (
          <Box
            sx={htmlContentStyles}
            dangerouslySetInnerHTML={{ __html: formatReportContent(result.ai_report_functionality) }}
          />
        )}
        {activeReport === 0 && !result.ai_report_functionality && (
          <Alert severity="info">
            Functionality analysis not available. Run analysis with AI enabled.
          </Alert>
        )}

        {/* Security Report */}
        {activeReport === 1 && result.ai_report_security && (
          <Box
            sx={htmlContentStyles}
            dangerouslySetInnerHTML={{ __html: formatReportContent(result.ai_report_security) }}
          />
        )}
        {activeReport === 1 && !result.ai_report_security && (
          <Alert severity="info">
            Security analysis not available. Run analysis with AI enabled.
          </Alert>
        )}

        {/* Architecture Diagram */}
        {activeReport === 2 && hasDiagrams && (
          <Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              AI-generated visual representation of the APK's architecture showing key components, data flows, and integration points.
            </Typography>
            {result.ai_architecture_diagram ? (
              <MermaidDiagram 
                code={result.ai_architecture_diagram}
                title="APK Architecture"
                maxHeight={600}
                showControls={true}
                showCodeToggle={true}
              />
            ) : (
              <Alert severity="info">
                Architecture diagram not available. This is generated when AI analysis is enabled.
              </Alert>
            )}
          </Box>
        )}

        {/* Data Flow Diagram */}
        {activeReport === 3 && result.ai_data_flow_diagram && (
          <Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Data flow and privacy visualization showing how sensitive data moves through the application.
            </Typography>
            <MermaidDiagram 
              code={result.ai_data_flow_diagram}
              title="Data Flow & Privacy"
              maxHeight={600}
              showControls={true}
              showCodeToggle={true}
            />
          </Box>
        )}
      </Box>
    </Paper>
  );
}

// ============================================================================
// AI-Powered APK Analysis Components
// ============================================================================

import type {
  ApkChatMessage,
  ApkChatRequest,
  ApkChatResponse,
  ThreatModelRequest,
  ThreatModelResponse,
  ExploitSuggestionRequest,
  ExploitSuggestionResponse,
  AnalysisWalkthroughResponse,
  WalkthroughStep,
  ChatExportRequest,
  CodeExplanationRequest,
  CodeExplanationResponse,
  CodeSearchAIRequest,
  CodeSearchAIResponse,
} from "../api/client";

// Chat Icon import
import ChatIcon from "@mui/icons-material/Chat";
import SchoolIcon from "@mui/icons-material/School";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import SendIcon from "@mui/icons-material/Send";
import LightbulbIcon from "@mui/icons-material/Lightbulb";
import SkipNextIcon from "@mui/icons-material/SkipNext";
import SkipPreviousIcon from "@mui/icons-material/SkipPrevious";
import HelpOutlineIcon from "@mui/icons-material/HelpOutline";
import AssessmentIcon from "@mui/icons-material/Assessment";
import TargetIcon from "@mui/icons-material/TrackChanges";
import MenuBookIcon from "@mui/icons-material/MenuBook";
import SaveAltIcon from "@mui/icons-material/SaveAlt";
import RadarIcon from "@mui/icons-material/Radar";

// APK AI Tools Container Component
function ApkAITools({ 
  analysisResult, 
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [activeAiTab, setActiveAiTab] = useState(0);
  const [beginnerMode, setBeginnerMode] = useState(false);
  
  // Cross-Class Vulnerability Scan State
  const [aiVulnScanResult, setAiVulnScanResult] = useState<AIVulnScanResult | null>(null);
  const [aiVulnScanLoading, setAiVulnScanLoading] = useState(false);
  const [aiVulnScanType, setAiVulnScanType] = useState<"quick" | "deep" | "focused">("quick");

  // AI Full Vulnerability Scan Handler
  const handleAiVulnScan = async () => {
    if (!jadxResult) return;
    
    setAiVulnScanLoading(true);
    setAiVulnScanResult(null);
    
    try {
      const res = await reverseEngineeringClient.aiVulnScan(
        jadxResult.output_directory,
        aiVulnScanType,
        ["authentication", "data_storage", "network", "crypto"]
      );
      setAiVulnScanResult(res);
    } catch (err) {
      console.error("AI vulnerability scan failed:", err);
    } finally {
      setAiVulnScanLoading(false);
    }
  };

  // Check if we have deep code context
  const hasDeepContext = !!jadxResult;

  return (
    <Paper sx={{ p: 3, mt: 3 }}>
      <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 2 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
          <Typography variant="h6" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="primary" /> AI-Powered Analysis Tools
          </Typography>
          {hasDeepContext ? (
            <Chip 
              icon={<CodeIcon />} 
              label="Deep Context (JADX)" 
              color="success" 
              size="small"
              variant="outlined"
            />
          ) : (
            <Chip 
              label="Basic Context (Quick Scan)" 
              color="warning" 
              size="small"
              variant="outlined"
            />
          )}
        </Box>
        <FormControlLabel
          control={
            <Switch 
              checked={beginnerMode} 
              onChange={(e) => setBeginnerMode(e.target.checked)}
              color="info"
            />
          }
          label={<Typography variant="body2">🎓 Beginner Mode</Typography>}
        />
      </Box>
      
      <Tabs 
        value={activeAiTab} 
        onChange={(_, v) => setActiveAiTab(v)}
        sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}
        variant="scrollable"
        scrollButtons="auto"
      >
        <Tab icon={<ChatIcon />} label="AI Chat" iconPosition="start" />
        <Tab icon={<TargetIcon />} label="Threat Model" iconPosition="start" />
        <Tab icon={<BugIcon />} label="Exploit Suggestions" iconPosition="start" />
        <Tab icon={<SchoolIcon />} label="Walkthrough" iconPosition="start" />
        <Tab 
          icon={<RadarIcon />} 
          label="Cross-Class Vuln Scan" 
          iconPosition="start"
          disabled={!hasDeepContext}
        />
      </Tabs>

      {activeAiTab === 0 && (
        <ApkAIChatPanel analysisResult={analysisResult} jadxResult={jadxResult} beginnerMode={beginnerMode} />
      )}
      {activeAiTab === 1 && (
        <ThreatModelViewer analysisResult={analysisResult} jadxResult={jadxResult} />
      )}
      {activeAiTab === 2 && (
        <ExploitSuggestionsPanel analysisResult={analysisResult} jadxResult={jadxResult} beginnerMode={beginnerMode} />
      )}
      {activeAiTab === 3 && (
        <WalkthroughPanel analysisResult={analysisResult} jadxResult={jadxResult} />
      )}
      {activeAiTab === 4 && (
        <CrossClassVulnScanPanel 
          jadxResult={jadxResult}
          aiVulnScanResult={aiVulnScanResult}
          aiVulnScanLoading={aiVulnScanLoading}
          aiVulnScanType={aiVulnScanType}
          setAiVulnScanType={setAiVulnScanType}
          onScan={handleAiVulnScan}
        />
      )}
    </Paper>
  );
}

// AI Chat Panel Component
function ApkAIChatPanel({ 
  analysisResult, 
  jadxResult,
  beginnerMode 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
  beginnerMode: boolean;
}) {
  const theme = useTheme();
  const [messages, setMessages] = useState<ApkChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [suggestedQuestions, setSuggestedQuestions] = useState<string[]>([
    "What are the most critical security issues in this APK?",
    "Explain the dangerous permissions and their risks",
    "Are there any signs of malware or suspicious behavior?",
    "What data could this app leak?",
    "How secure is the app's cryptographic implementation?",
  ]);
  const [learningTip, setLearningTip] = useState<string | null>(null);
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null);
  const [exporting, setExporting] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (message?: string) => {
    const msgToSend = message || inputMessage.trim();
    if (!msgToSend) return;

    const userMessage: ApkChatMessage = {
      role: "user",
      content: msgToSend,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsLoading(true);

    try {
      const request: ApkChatRequest = {
        message: msgToSend,
        conversation_history: messages,
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        beginner_mode: beginnerMode,
      };

      const response = await reverseEngineeringClient.chatAboutApk(request);

      const assistantMessage: ApkChatMessage = {
        role: "assistant",
        content: response.response,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
      if (response.suggested_questions?.length > 0) {
        setSuggestedQuestions(response.suggested_questions);
      }
      if (response.learning_tip) {
        setLearningTip(response.learning_tip);
      }
    } catch (error) {
      console.error("Chat error:", error);
      const errorMessage: ApkChatMessage = {
        role: "assistant",
        content: "Sorry, I encountered an error processing your question. Please try again.",
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleExportChat = async (format: "markdown" | "json" | "pdf") => {
    setExportMenuAnchor(null);
    if (messages.length === 0) return;
    
    setExporting(true);
    try {
      const request: ChatExportRequest = {
        messages: messages,
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        format: format,
      };
      
      const blob = await reverseEngineeringClient.exportApkChat(request);
      
      // Create download link
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "markdown" ? "md" : format;
      a.download = `${analysisResult.package_name?.split(".").pop() || "apk"}_chat.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setExporting(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
    setLearningTip(null);
  };

  return (
    <Box>
      {/* Header with actions */}
      <Box sx={{ display: "flex", justifyContent: "flex-end", gap: 1, mb: 1 }}>
        {messages.length > 0 && (
          <>
            <Button
              size="small"
              startIcon={exporting ? <CircularProgress size={16} /> : <SaveAltIcon />}
              onClick={(e) => setExportMenuAnchor(e.currentTarget)}
              disabled={exporting}
            >
              Save Chat
            </Button>
            <Menu
              anchorEl={exportMenuAnchor}
              open={Boolean(exportMenuAnchor)}
              onClose={() => setExportMenuAnchor(null)}
            >
              <MenuItem onClick={() => handleExportChat("markdown")}>
                <DocIcon sx={{ mr: 1 }} /> Markdown (.md)
              </MenuItem>
              <MenuItem onClick={() => handleExportChat("json")}>
                <CodeIcon sx={{ mr: 1 }} /> JSON (.json)
              </MenuItem>
              <MenuItem onClick={() => handleExportChat("pdf")}>
                <PdfIcon sx={{ mr: 1 }} /> PDF (.pdf)
              </MenuItem>
            </Menu>
            <Button
              size="small"
              color="error"
              startIcon={<DeleteIcon />}
              onClick={clearChat}
            >
              Clear
            </Button>
          </>
        )}
      </Box>

      {/* Chat Messages */}
      <Paper 
        sx={{ 
          height: 400, 
          overflow: "auto", 
          p: 2, 
          mb: 2, 
          bgcolor: alpha(theme.palette.background.default, 0.5) 
        }}
      >
        {messages.length === 0 && (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <AiIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
            <Typography variant="h6" color="text.secondary" gutterBottom>
              Ask me anything about this APK
            </Typography>
            <Typography variant="body2" color="text.secondary">
              I can help explain security findings, suggest remediation steps, 
              and answer questions about the analysis results.
            </Typography>
          </Box>
        )}
        
        {messages.map((msg, idx) => (
          <Box
            key={idx}
            sx={{
              display: "flex",
              justifyContent: msg.role === "user" ? "flex-end" : "flex-start",
              mb: 2,
            }}
          >
            <Paper
              sx={{
                p: 2,
                maxWidth: "80%",
                bgcolor: msg.role === "user" 
                  ? alpha(theme.palette.primary.main, 0.1)
                  : alpha(theme.palette.grey[500], 0.1),
                borderRadius: 2,
              }}
            >
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                {msg.content}
              </Typography>
              <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
                {msg.timestamp ? new Date(msg.timestamp).toLocaleTimeString() : ""}
              </Typography>
            </Paper>
          </Box>
        ))}
        
        {isLoading && (
          <Box sx={{ display: "flex", gap: 1, alignItems: "center", ml: 2 }}>
            <CircularProgress size={20} />
            <Typography variant="body2" color="text.secondary">
              Analyzing...
            </Typography>
          </Box>
        )}
        <div ref={messagesEndRef} />
      </Paper>

      {/* Learning Tip */}
      {learningTip && beginnerMode && (
        <Alert 
          severity="info" 
          icon={<LightbulbIcon />}
          sx={{ mb: 2 }}
          onClose={() => setLearningTip(null)}
        >
          <Typography variant="subtitle2" gutterBottom>💡 Learning Tip</Typography>
          <Typography variant="body2">{learningTip}</Typography>
        </Alert>
      )}

      {/* Suggested Questions */}
      <Box sx={{ mb: 2 }}>
        <Typography variant="caption" color="text.secondary" gutterBottom>
          Suggested questions:
        </Typography>
        <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1, mt: 0.5 }}>
          {suggestedQuestions.slice(0, 4).map((q, idx) => (
            <Chip
              key={idx}
              label={q}
              size="small"
              variant="outlined"
              onClick={() => handleSendMessage(q)}
              disabled={isLoading}
              sx={{ 
                cursor: "pointer",
                "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) }
              }}
            />
          ))}
        </Box>
      </Box>

      {/* Input */}
      <Box sx={{ display: "flex", gap: 1 }}>
        <TextField
          fullWidth
          placeholder="Ask about the APK analysis..."
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={(e) => e.key === "Enter" && !e.shiftKey && handleSendMessage()}
          disabled={isLoading}
          multiline
          maxRows={3}
        />
        <Button
          variant="contained"
          onClick={() => handleSendMessage()}
          disabled={isLoading || !inputMessage.trim()}
          sx={{ minWidth: 100 }}
        >
          <SendIcon />
        </Button>
      </Box>
    </Box>
  );
}

// Threat Model Viewer Component
function ThreatModelViewer({ 
  analysisResult,
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [threatModel, setThreatModel] = useState<ThreatModelResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [attackerProfile, setAttackerProfile] = useState<"script_kiddie" | "skilled" | "nation_state">("skilled");

  const generateThreatModel = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: ThreatModelRequest = {
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        attacker_profile: attackerProfile,
      };
      const response = await reverseEngineeringClient.generateThreatModel(request);
      setThreatModel(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate threat model");
    } finally {
      setIsLoading(false);
    }
  };

  if (!threatModel) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <TargetIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>Generate AI Threat Model</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Create a comprehensive threat model based on the APK analysis findings.
        </Typography>
        
        <Box sx={{ mb: 3, display: "flex", justifyContent: "center", gap: 1 }}>
          <Typography variant="body2" sx={{ alignSelf: "center" }}>Attacker Profile:</Typography>
          {(["script_kiddie", "skilled", "nation_state"] as const).map((profile) => (
            <Chip
              key={profile}
              label={profile.replace("_", " ").toUpperCase()}
              variant={attackerProfile === profile ? "filled" : "outlined"}
              color={attackerProfile === profile ? "primary" : "default"}
              onClick={() => setAttackerProfile(profile)}
            />
          ))}
        </Box>

        <Button
          variant="contained"
          onClick={generateThreatModel}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Generate Threat Model"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  return (
    <Box>
      {/* Executive Summary */}
      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>Executive Summary</Typography>
        <Typography variant="body2">{threatModel.executive_summary}</Typography>
      </Alert>

      {/* Threat Actors */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecurityIcon color="error" /> Threat Actors ({threatModel.threat_actors.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {threatModel.threat_actors.map((actor, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                  <Typography variant="subtitle1" fontWeight="bold">{actor.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {actor.description}
                  </Typography>
                  <Box sx={{ display: "flex", gap: 1 }}>
                    <Chip label={`Capability: ${actor.capability}`} size="small" />
                    <Chip label={`Likelihood: ${actor.likelihood}`} size="small" />
                  </Box>
                  <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                    <strong>Motivation:</strong> {actor.motivation}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Attack Scenarios */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="warning" /> Attack Scenarios ({threatModel.attack_scenarios.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {threatModel.attack_scenarios.map((scenario, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.warning.main, 0.05) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">{scenario.name}</Typography>
                <Chip 
                  label={scenario.severity} 
                  size="small" 
                  sx={{
                    bgcolor: alpha(getSeverityColor(scenario.severity), 0.2),
                    color: getSeverityColor(scenario.severity),
                  }}
                />
              </Box>
              <Typography variant="body2" sx={{ mb: 2 }}>{scenario.description}</Typography>
              
              <Typography variant="caption" fontWeight="bold">Attack Steps:</Typography>
              <List dense>
                {scenario.attack_steps.map((step, stepIdx) => (
                  <ListItem key={stepIdx} sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 30 }}>
                      <Typography variant="caption">{stepIdx + 1}.</Typography>
                    </ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{step}</Typography>} />
                  </ListItem>
                ))}
              </List>
              
              <Typography variant="caption" color="error.main">
                <strong>Impact:</strong> {scenario.impact}
              </Typography>
              
              {scenario.mitre_techniques.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  <Typography variant="caption">MITRE ATT&CK: </Typography>
                  {scenario.mitre_techniques.map((tech, techIdx) => (
                    <Chip key={techIdx} label={tech} size="small" variant="outlined" sx={{ mr: 0.5 }} />
                  ))}
                </Box>
              )}
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Attack Tree */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AssessmentIcon color="primary" /> Attack Tree
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="h6" gutterBottom>🎯 {threatModel.attack_tree.goal}</Typography>
            {threatModel.attack_tree.branches.map((branch, idx) => (
              <Box key={idx} sx={{ ml: 2, mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <Typography variant="subtitle2">📍 {branch.method}</Typography>
                  <Chip 
                    label={branch.difficulty} 
                    size="small" 
                    color={branch.difficulty === "Easy" ? "success" : branch.difficulty === "Medium" ? "warning" : "error"}
                  />
                </Box>
                {branch.sub_branches.length > 0 && (
                  <List dense sx={{ ml: 2 }}>
                    {branch.sub_branches.map((sub, subIdx) => (
                      <ListItem key={subIdx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">↳ {sub}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Box>
            ))}
          </Paper>
        </AccordionDetails>
      </Accordion>

      {/* MITRE ATT&CK Mappings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <ShieldIcon color="secondary" /> MITRE ATT&CK Mappings ({threatModel.mitre_attack_mappings.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Technique</TableCell>
                  <TableCell>Tactic</TableCell>
                  <TableCell>Relevance</TableCell>
                  <TableCell>Finding</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {threatModel.mitre_attack_mappings.map((mapping, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Chip label={mapping.technique_id} size="small" color="secondary" />
                      <Typography variant="body2">{mapping.technique_name}</Typography>
                    </TableCell>
                    <TableCell>{mapping.tactic}</TableCell>
                    <TableCell>{mapping.relevance}</TableCell>
                    <TableCell>
                      <Typography variant="caption">{mapping.finding_reference}</Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* Risk Matrix */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <WarningIcon color="error" /> Risk Matrix
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {threatModel.risk_matrix.critical_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#dc2626", 0.1), border: `1px solid ${alpha("#dc2626", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#dc2626" gutterBottom>🔴 Critical Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.critical_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.high_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ea580c", 0.1), border: `1px solid ${alpha("#ea580c", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#ea580c" gutterBottom>🟠 High Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.high_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.medium_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#ca8a04", 0.1), border: `1px solid ${alpha("#ca8a04", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#ca8a04" gutterBottom>🟡 Medium Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.medium_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
            {threatModel.risk_matrix.low_risks.length > 0 && (
              <Grid item xs={12} md={6}>
                <Paper sx={{ p: 2, bgcolor: alpha("#16a34a", 0.1), border: `1px solid ${alpha("#16a34a", 0.3)}` }}>
                  <Typography variant="subtitle2" color="#16a34a" gutterBottom>🟢 Low Risks</Typography>
                  <List dense>
                    {threatModel.risk_matrix.low_risks.map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText primary={<Typography variant="body2">{risk}</Typography>} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
            )}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Prioritized Threats */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GpsFixedIcon color="primary" /> Prioritized Threats ({threatModel.prioritized_threats.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {threatModel.prioritized_threats.map((threat, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, display: "flex", gap: 2 }}>
              <Box sx={{ 
                width: 50, 
                height: 50, 
                borderRadius: "50%", 
                display: "flex", 
                alignItems: "center", 
                justifyContent: "center",
                bgcolor: alpha(theme.palette.primary.main, 0.1),
                color: theme.palette.primary.main,
                fontWeight: "bold",
                fontSize: "1.2rem"
              }}>
                #{threat.rank}
              </Box>
              <Box sx={{ flex: 1 }}>
                <Typography variant="subtitle1" fontWeight="bold">{threat.threat}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {threat.rationale}
                </Typography>
                <Chip label={`Risk Score: ${threat.risk_score}/100`} size="small" color="warning" sx={{ mr: 1 }} />
                <Typography variant="caption" color="success.main">
                  <strong>Recommendation:</strong> {threat.recommendation}
                </Typography>
              </Box>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      <Button
        variant="outlined"
        onClick={() => setThreatModel(null)}
        sx={{ mt: 2 }}
      >
        Regenerate Threat Model
      </Button>
    </Box>
  );
}

// Exploit Suggestions Panel Component
function ExploitSuggestionsPanel({ 
  analysisResult,
  jadxResult,
  beginnerMode 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
  beginnerMode: boolean;
}) {
  const theme = useTheme();
  const [exploitSuggestions, setExploitSuggestions] = useState<ExploitSuggestionResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [skillLevel, setSkillLevel] = useState<"beginner" | "intermediate" | "advanced">("intermediate");
  const [includePoc, setIncludePoc] = useState(true);

  const generateExploitSuggestions = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: ExploitSuggestionRequest = {
        analysis_context: analysisResult as unknown as Record<string, unknown>,
        include_poc: includePoc,
        skill_level: skillLevel,
      };
      const response = await reverseEngineeringClient.getExploitSuggestions(request);
      setExploitSuggestions(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate exploit suggestions");
    } finally {
      setIsLoading(false);
    }
  };

  if (!exploitSuggestions) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <BugIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>AI Exploit Suggestions</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Generate exploitation paths and proof-of-concept scripts for educational and defensive purposes.
        </Typography>
        
        <Alert severity="warning" sx={{ mb: 3, maxWidth: 500, mx: "auto" }}>
          <Typography variant="body2">
            ⚠️ This feature is for <strong>educational and defensive security research only</strong>. 
            Use responsibly and only on applications you own or have permission to test.
          </Typography>
        </Alert>

        <Box sx={{ mb: 3, display: "flex", justifyContent: "center", gap: 2, flexWrap: "wrap" }}>
          <Box>
            <Typography variant="caption" color="text.secondary">Skill Level:</Typography>
            <Box sx={{ display: "flex", gap: 1, mt: 0.5 }}>
              {(["beginner", "intermediate", "advanced"] as const).map((level) => (
                <Chip
                  key={level}
                  label={level.toUpperCase()}
                  variant={skillLevel === level ? "filled" : "outlined"}
                  color={skillLevel === level ? "primary" : "default"}
                  onClick={() => setSkillLevel(level)}
                />
              ))}
            </Box>
          </Box>
          <FormControlLabel
            control={<Switch checked={includePoc} onChange={(e) => setIncludePoc(e.target.checked)} />}
            label="Include PoC Scripts"
          />
        </Box>

        <Button
          variant="contained"
          color="warning"
          onClick={generateExploitSuggestions}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Generate Exploit Suggestions"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  return (
    <Box>
      {/* Difficulty Assessment */}
      <Alert 
        severity={
          exploitSuggestions.difficulty_assessment.overall_difficulty === "Easy" ? "error" :
          exploitSuggestions.difficulty_assessment.overall_difficulty === "Medium" ? "warning" : "info"
        }
        sx={{ mb: 3 }}
      >
        <Typography variant="subtitle2" gutterBottom>Difficulty Assessment</Typography>
        <Grid container spacing={2}>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Overall</Typography>
            <Typography variant="body2" fontWeight="bold">
              {exploitSuggestions.difficulty_assessment.overall_difficulty}
            </Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Time Estimate</Typography>
            <Typography variant="body2">{exploitSuggestions.difficulty_assessment.time_estimate}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Success Probability</Typography>
            <Typography variant="body2">{exploitSuggestions.difficulty_assessment.success_probability}</Typography>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="caption" color="text.secondary">Skills Required:</Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
              {exploitSuggestions.difficulty_assessment.skill_requirements.map((skill, idx) => (
                <Chip key={idx} label={skill} size="small" variant="outlined" />
              ))}
            </Box>
          </Grid>
        </Grid>
      </Alert>

      {/* Vulnerabilities */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="error" /> Exploitable Vulnerabilities ({exploitSuggestions.vulnerabilities.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {exploitSuggestions.vulnerabilities.map((vuln, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(getSeverityColor(vuln.severity), 0.05) }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                <Chip 
                  label={vuln.severity} 
                  size="small"
                  sx={{
                    bgcolor: alpha(getSeverityColor(vuln.severity), 0.2),
                    color: getSeverityColor(vuln.severity),
                  }}
                />
                <Typography variant="subtitle1" fontWeight="bold">{vuln.name}</Typography>
                <Chip label={vuln.category} size="small" variant="outlined" />
              </Box>
              <Typography variant="body2" sx={{ mb: 1 }}>{vuln.description}</Typography>
              <Typography variant="caption">
                <strong>Root Cause:</strong> {vuln.root_cause}
              </Typography>
              <br />
              <Typography variant="caption" color="text.secondary">
                <strong>Affected:</strong> {vuln.affected_component}
              </Typography>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Exploitation Paths */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <GpsFixedIcon color="warning" /> Exploitation Paths ({exploitSuggestions.exploitation_paths.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          {exploitSuggestions.exploitation_paths.map((path, idx) => (
            <Paper key={idx} sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle1" fontWeight="bold" gutterBottom>{path.name}</Typography>
              
              <Typography variant="caption" fontWeight="bold">Prerequisites:</Typography>
              <List dense sx={{ mb: 1 }}>
                {path.prerequisites.map((prereq, pIdx) => (
                  <ListItem key={pIdx} sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 24 }}>✓</ListItemIcon>
                    <ListItemText primary={<Typography variant="body2">{prereq}</Typography>} />
                  </ListItem>
                ))}
              </List>

              <Typography variant="caption" fontWeight="bold">Exploitation Steps:</Typography>
              <List dense sx={{ mb: 1 }}>
                {path.steps.map((step, sIdx) => (
                  <ListItem key={sIdx} sx={{ py: 0.5, flexDirection: "column", alignItems: "flex-start" }}>
                    <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      <Chip label={step.step} size="small" color="primary" />
                      <Typography variant="body2">{step.action}</Typography>
                    </Box>
                    {step.command && (
                      <Paper sx={{ p: 1, mt: 0.5, bgcolor: alpha(theme.palette.grey[900], 0.9), width: "100%" }}>
                        <Typography variant="caption" fontFamily="monospace" color="success.light">
                          $ {step.command}
                        </Typography>
                      </Paper>
                    )}
                    <Typography variant="caption" color="text.secondary">
                      Expected: {step.expected_result}
                    </Typography>
                  </ListItem>
                ))}
              </List>

              <Typography variant="caption" color="error.main">
                <strong>Impact:</strong> {path.impact}
              </Typography>
            </Paper>
          ))}
        </AccordionDetails>
      </Accordion>

      {/* Required Tools */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon color="primary" /> Required Tools ({exploitSuggestions.tools_required.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {exploitSuggestions.tools_required.map((tool, idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{tool.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                    {tool.purpose}
                  </Typography>
                  <Typography variant="caption" display="block">
                    <strong>Install:</strong> <code>{tool.installation}</code>
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    <strong>Example:</strong> {tool.usage_example}
                  </Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* PoC Scripts */}
      {exploitSuggestions.poc_scripts.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <CodeIcon color="secondary" /> Proof-of-Concept Scripts ({exploitSuggestions.poc_scripts.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {exploitSuggestions.poc_scripts.map((poc, idx) => (
              <Paper key={idx} sx={{ p: 2, mb: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{poc.name}</Typography>
                  <Chip label={poc.language} size="small" color="secondary" />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {poc.description}
                </Typography>
                <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.grey[900], 0.95), overflow: "auto", maxHeight: 300 }}>
                  <pre style={{ margin: 0, color: "#e0e0e0", fontSize: "0.8rem" }}>
                    {poc.code}
                  </pre>
                </Paper>
                <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                  <strong>Usage:</strong> {poc.usage}
                </Typography>
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
      )}

      {/* Mitigation Bypasses */}
      {exploitSuggestions.mitigation_bypasses.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <ShieldIcon color="warning" /> Mitigation Bypasses ({exploitSuggestions.mitigation_bypasses.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            {exploitSuggestions.mitigation_bypasses.map((bypass, idx) => (
              <Paper key={idx} sx={{ p: 2, mb: 2 }}>
                <Typography variant="subtitle2" fontWeight="bold">{bypass.protection}</Typography>
                <Typography variant="body2" sx={{ mb: 1 }}>{bypass.bypass_method}</Typography>
                <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                  <Chip 
                    label={`Difficulty: ${bypass.difficulty}`} 
                    size="small"
                    color={bypass.difficulty === "Easy" ? "success" : bypass.difficulty === "Medium" ? "warning" : "error"}
                  />
                  <Chip label={`Detection Risk: ${bypass.detection_risk}`} size="small" variant="outlined" />
                </Box>
                {bypass.tools.length > 0 && (
                  <Typography variant="caption" sx={{ mt: 1, display: "block" }}>
                    <strong>Tools:</strong> {bypass.tools.join(", ")}
                  </Typography>
                )}
              </Paper>
            ))}
          </AccordionDetails>
        </Accordion>
      )}

      <Button
        variant="outlined"
        onClick={() => setExploitSuggestions(null)}
        sx={{ mt: 2 }}
      >
        Regenerate Suggestions
      </Button>
    </Box>
  );
}

// Walkthrough Panel Component
function WalkthroughPanel({ 
  analysisResult,
  jadxResult 
}: { 
  analysisResult: ApkAnalysisResult;
  jadxResult?: JadxDecompilationResult | null;
}) {
  const theme = useTheme();
  const [walkthrough, setWalkthrough] = useState<AnalysisWalkthroughResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [currentStep, setCurrentStep] = useState(0);
  const [showGlossary, setShowGlossary] = useState(false);

  const generateWalkthrough = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await reverseEngineeringClient.getAnalysisWalkthrough(
        analysisResult as unknown as Record<string, unknown>
      );
      setWalkthrough(response);
      setCurrentStep(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate walkthrough");
    } finally {
      setIsLoading(false);
    }
  };

  if (!walkthrough) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <SchoolIcon sx={{ fontSize: 48, color: "text.secondary", mb: 2 }} />
        <Typography variant="h6" gutterBottom>🎓 Educational Walkthrough</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          Get a step-by-step guided tour of the APK analysis with beginner-friendly explanations.
        </Typography>
        
        <Button
          variant="contained"
          color="info"
          onClick={generateWalkthrough}
          disabled={isLoading}
          startIcon={isLoading ? <CircularProgress size={20} /> : <PlayArrowIcon />}
        >
          {isLoading ? "Generating..." : "Start Walkthrough"}
        </Button>
        
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Box>
    );
  }

  const step = walkthrough.steps[currentStep];

  return (
    <Box>
      {/* Progress Bar */}
      <Box sx={{ mb: 3 }}>
        <Box sx={{ display: "flex", justifyContent: "space-between", mb: 1 }}>
          <Typography variant="body2">
            Step {currentStep + 1} of {walkthrough.total_steps}
          </Typography>
          <Typography variant="body2">
            {step.progress_percent}% Complete
          </Typography>
        </Box>
        <LinearProgress 
          variant="determinate" 
          value={step.progress_percent} 
          sx={{ height: 8, borderRadius: 4 }}
        />
      </Box>

      {/* Step Content */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
          <Chip 
            label={step.phase} 
            color="primary" 
            size="small"
          />
          {step.severity && (
            <Chip 
              label={step.severity} 
              size="small"
              sx={{
                bgcolor: alpha(getSeverityColor(step.severity), 0.2),
                color: getSeverityColor(step.severity),
              }}
            />
          )}
          {step.findings_count > 0 && (
            <Chip 
              label={`${step.findings_count} findings`} 
              size="small" 
              variant="outlined"
            />
          )}
        </Box>

        <Typography variant="h5" gutterBottom>{step.title}</Typography>
        <Typography variant="body1" sx={{ mb: 3 }}>{step.description}</Typography>

        <Divider sx={{ my: 2 }} />

        {/* Technical Detail */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.grey[500], 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <CodeIcon fontSize="small" /> Technical Detail
          </Typography>
          <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
            {step.technical_detail}
          </Typography>
        </Paper>

        {/* Beginner Explanation */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SchoolIcon fontSize="small" color="info" /> Beginner Explanation
          </Typography>
          <Typography variant="body2">{step.beginner_explanation}</Typography>
        </Paper>

        {/* Why It Matters */}
        <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.1) }}>
          <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LightbulbIcon fontSize="small" color="warning" /> Why This Matters
          </Typography>
          <Typography variant="body2">{step.why_it_matters}</Typography>
        </Paper>
      </Paper>

      {/* Navigation */}
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(0)}
          disabled={currentStep === 0}
          startIcon={<FirstPageIcon />}
        >
          First
        </Button>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(currentStep - 1)}
          disabled={currentStep === 0}
          startIcon={<SkipPreviousIcon />}
        >
          Previous
        </Button>
        <Typography variant="body2">
          {walkthrough.steps.map((_, idx) => (
            <IconButton
              key={idx}
              size="small"
              onClick={() => setCurrentStep(idx)}
              sx={{
                mx: 0.25,
                width: 24,
                height: 24,
                bgcolor: idx === currentStep ? "primary.main" : alpha(theme.palette.grey[500], 0.2),
                color: idx === currentStep ? "white" : "text.secondary",
                fontSize: "0.7rem",
                "&:hover": { bgcolor: idx === currentStep ? "primary.dark" : alpha(theme.palette.grey[500], 0.4) },
              }}
            >
              {idx + 1}
            </IconButton>
          ))}
        </Typography>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(currentStep + 1)}
          disabled={currentStep === walkthrough.total_steps - 1}
          endIcon={<SkipNextIcon />}
        >
          Next
        </Button>
        <Button
          variant="outlined"
          onClick={() => setCurrentStep(walkthrough.total_steps - 1)}
          disabled={currentStep === walkthrough.total_steps - 1}
          endIcon={<LastPageIcon />}
        >
          Last
        </Button>
      </Box>

      {/* Glossary Toggle */}
      <Accordion expanded={showGlossary} onChange={() => setShowGlossary(!showGlossary)}>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <MenuBookIcon color="primary" /> Glossary ({Object.keys(walkthrough.glossary).length} terms)
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            {Object.entries(walkthrough.glossary).map(([term, definition], idx) => (
              <Grid item xs={12} md={6} key={idx}>
                <Paper sx={{ p: 2 }}>
                  <Typography variant="subtitle2" fontWeight="bold">{term}</Typography>
                  <Typography variant="body2" color="text.secondary">{definition}</Typography>
                </Paper>
              </Grid>
            ))}
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Learning Resources */}
      {walkthrough.learning_resources.length > 0 && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <LinkIcon color="primary" /> Learning Resources ({walkthrough.learning_resources.length})
            </Typography>
          </AccordionSummary>
          <AccordionDetails>
            <List dense>
              {walkthrough.learning_resources.map((resource, idx) => (
                <ListItem key={idx} component="a" href={resource.url} target="_blank" sx={{ 
                  cursor: "pointer",
                  "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) }
                }}>
                  <ListItemIcon><LinkIcon color="primary" /></ListItemIcon>
                  <ListItemText 
                    primary={resource.title}
                    secondary={resource.description}
                  />
                </ListItem>
              ))}
            </List>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Next Steps */}
      {walkthrough.next_steps.length > 0 && (
        <Alert severity="success" sx={{ mt: 2 }}>
          <Typography variant="subtitle2" gutterBottom>🎯 Recommended Next Steps</Typography>
          <List dense>
            {walkthrough.next_steps.map((nextStep, idx) => (
              <ListItem key={idx} sx={{ py: 0 }}>
                <ListItemIcon sx={{ minWidth: 24 }}>{idx + 1}.</ListItemIcon>
                <ListItemText primary={<Typography variant="body2">{nextStep}</Typography>} />
              </ListItem>
            ))}
          </List>
        </Alert>
      )}

      <Button
        variant="outlined"
        onClick={() => setWalkthrough(null)}
        sx={{ mt: 2 }}
      >
        Restart Walkthrough
      </Button>
    </Box>
  );
}

// Cross-Class Vulnerability Scan Panel Component
function CrossClassVulnScanPanel({
  jadxResult,
  aiVulnScanResult,
  aiVulnScanLoading,
  aiVulnScanType,
  setAiVulnScanType,
  onScan,
}: {
  jadxResult?: JadxDecompilationResult | null;
  aiVulnScanResult: AIVulnScanResult | null;
  aiVulnScanLoading: boolean;
  aiVulnScanType: "quick" | "deep" | "focused";
  setAiVulnScanType: (type: "quick" | "deep" | "focused") => void;
  onScan: () => void;
}) {
  const theme = useTheme();

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case "critical": return "#dc2626";
      case "high": return "#ea580c";
      case "medium": return "#ca8a04";
      case "low": return "#16a34a";
      default: return "#6b7280";
    }
  };

  if (!jadxResult) {
    return (
      <Box sx={{ textAlign: "center", py: 4 }}>
        <RadarIcon sx={{ fontSize: 64, color: theme.palette.grey[400], mb: 2 }} />
        <Typography variant="h6" color="text.secondary" gutterBottom>
          Decompilation Required
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2, maxWidth: 400, mx: "auto" }}>
          The Cross-Class Vulnerability Scanner analyzes decompiled Java source code to find security issues across the entire codebase.
        </Typography>
        <Button
          variant="outlined"
          onClick={() => {
            document.getElementById('advanced-apk-analysis')?.scrollIntoView({ behavior: 'smooth' });
          }}
        >
          Go to JADX Decompiler
        </Button>
      </Box>
    );
  }

  return (
    <Box>
      {/* Scan Controls */}
      <Box sx={{ 
        display: "flex", 
        alignItems: "center", 
        justifyContent: "space-between", 
        mb: 3,
        p: 2,
        borderRadius: 1,
        bgcolor: alpha(theme.palette.error.main, 0.05),
        border: `1px solid ${alpha(theme.palette.error.main, 0.2)}`
      }}>
        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <RadarIcon color="error" />
          <Box>
            <Typography variant="subtitle1" fontWeight="bold">
              AI Cross-Class Vulnerability Scan
            </Typography>
            <Typography variant="caption" color="text.secondary">
              Scans {jadxResult.total_classes} classes for security vulnerabilities
            </Typography>
          </Box>
        </Box>
        <Box sx={{ display: "flex", gap: 1, alignItems: "center" }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <Select
              value={aiVulnScanType}
              onChange={(e) => setAiVulnScanType(e.target.value as "quick" | "deep" | "focused")}
            >
              <MenuItem value="quick">⚡ Quick Scan</MenuItem>
              <MenuItem value="deep">🔍 Deep Scan</MenuItem>
              <MenuItem value="focused">🎯 Focused Scan</MenuItem>
            </Select>
          </FormControl>
          <Button 
            variant="contained" 
            color="error"
            onClick={onScan}
            disabled={aiVulnScanLoading}
            startIcon={aiVulnScanLoading ? <CircularProgress size={16} /> : <RadarIcon />}
          >
            {aiVulnScanLoading ? "Scanning..." : "Run Scan"}
          </Button>
        </Box>
      </Box>

      {/* Scan Type Description */}
      <Alert severity="info" sx={{ mb: 2 }}>
        <Typography variant="body2">
          {aiVulnScanType === "quick" && "⚡ Quick Scan: Fast analysis of critical security patterns (< 1 minute)"}
          {aiVulnScanType === "deep" && "🔍 Deep Scan: Comprehensive analysis including data flow tracking (2-5 minutes)"}
          {aiVulnScanType === "focused" && "🎯 Focused Scan: Targeted analysis of auth, storage, network & crypto (1-2 minutes)"}
        </Typography>
      </Alert>

      {/* Loading State */}
      {aiVulnScanLoading && (
        <Box sx={{ textAlign: "center", py: 4 }}>
          <CircularProgress color="error" />
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            AI is scanning entire codebase for vulnerabilities...
          </Typography>
          <Typography variant="caption" color="text.secondary">
            This may take a minute for large apps
          </Typography>
        </Box>
      )}

      {/* Results */}
      {aiVulnScanResult && !aiVulnScanLoading && (
        <Box>
          {/* Overall Risk */}
          <Paper sx={{ 
            p: 2, 
            mb: 2,
            bgcolor: alpha(getSeverityColor(aiVulnScanResult.overall_risk), 0.1),
            border: `2px solid ${getSeverityColor(aiVulnScanResult.overall_risk)}`
          }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
              <Chip 
                label={`${aiVulnScanResult.overall_risk.toUpperCase()} RISK`} 
                sx={{ 
                  bgcolor: getSeverityColor(aiVulnScanResult.overall_risk),
                  color: "white",
                  fontWeight: 700
                }} 
              />
              <Typography variant="body1">{aiVulnScanResult.summary}</Typography>
            </Box>
          </Paper>

          {/* Risk Summary */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#dc2626", 0.1) }}>
                <Typography variant="h4" color="error">{aiVulnScanResult.risk_summary.critical}</Typography>
                <Typography variant="body2">Critical</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#ea580c", 0.1) }}>
                <Typography variant="h4" sx={{ color: "#ea580c" }}>{aiVulnScanResult.risk_summary.high}</Typography>
                <Typography variant="body2">High</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#ca8a04", 0.1) }}>
                <Typography variant="h4" sx={{ color: "#ca8a04" }}>{aiVulnScanResult.risk_summary.medium}</Typography>
                <Typography variant="body2">Medium</Typography>
              </Paper>
            </Grid>
            <Grid item xs={3}>
              <Paper sx={{ p: 2, textAlign: "center", bgcolor: alpha("#16a34a", 0.1) }}>
                <Typography variant="h4" color="success.main">{aiVulnScanResult.risk_summary.low}</Typography>
                <Typography variant="body2">Low</Typography>
              </Paper>
            </Grid>
          </Grid>

          {/* Vulnerability Details */}
          <Typography variant="h6" gutterBottom>
            Discovered Vulnerabilities ({aiVulnScanResult.vulnerabilities.length})
          </Typography>
          
          {aiVulnScanResult.vulnerabilities.length === 0 ? (
            <Alert severity="success" sx={{ mb: 2 }}>
              No vulnerabilities found in the scanned code!
            </Alert>
          ) : (
            <List>
              {aiVulnScanResult.vulnerabilities.map((vuln, idx) => (
                <Paper key={idx} sx={{ mb: 1, overflow: "hidden" }}>
                  <ListItem sx={{ 
                    borderLeft: `4px solid ${getSeverityColor(vuln.severity)}`,
                    bgcolor: alpha(getSeverityColor(vuln.severity), 0.05)
                  }}>
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, flexWrap: "wrap" }}>
                          <Chip 
                            label={vuln.severity} 
                            size="small" 
                            sx={{ 
                              bgcolor: getSeverityColor(vuln.severity),
                              color: "white",
                              fontWeight: 600,
                              textTransform: "uppercase"
                            }}
                          />
                          <Typography variant="subtitle1" fontWeight="bold">
                            {vuln.title}
                          </Typography>
                          {vuln.cwe_id && (
                            <Chip label={vuln.cwe_id} size="small" variant="outlined" />
                          )}
                        </Box>
                      }
                      secondary={
                        <Box sx={{ mt: 1 }}>
                          <Typography variant="body2" color="text.secondary" paragraph>
                            {vuln.description}
                          </Typography>
                          <Typography variant="caption" sx={{ 
                            fontFamily: "monospace",
                            bgcolor: alpha(theme.palette.common.black, 0.05),
                            p: 0.5,
                            borderRadius: 0.5,
                            display: "block",
                            mb: 1
                          }}>
                            📍 {vuln.affected_class}.{vuln.affected_method}
                          </Typography>
                          {vuln.code_snippet && (
                            <Box sx={{
                              bgcolor: alpha(theme.palette.common.black, 0.05),
                              p: 1,
                              borderRadius: 1,
                              mb: 1,
                              fontFamily: "monospace",
                              fontSize: "0.75rem",
                              overflow: "auto",
                              maxHeight: 100
                            }}>
                              <pre style={{ margin: 0 }}>{vuln.code_snippet}</pre>
                            </Box>
                          )}
                          {vuln.remediation && (
                            <Alert severity="info" sx={{ mt: 1 }}>
                              <Typography variant="body2">
                                <strong>Remediation:</strong> {vuln.remediation}
                              </Typography>
                            </Alert>
                          )}
                        </Box>
                      }
                    />
                  </ListItem>
                </Paper>
              ))}
            </List>
          )}

          {/* Attack Chains */}
          {aiVulnScanResult.attack_chains && aiVulnScanResult.attack_chains.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" gutterBottom>
                🔗 Attack Chains
              </Typography>
              {aiVulnScanResult.attack_chains.map((chain, idx) => (
                <Paper key={idx} sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                    <Typography variant="subtitle1" fontWeight="bold">{chain.name}</Typography>
                    <Chip label={chain.likelihood} size="small" color={
                      chain.likelihood === "high" ? "error" : 
                      chain.likelihood === "medium" ? "warning" : "info"
                    } />
                  </Box>
                  <Typography variant="body2" color="text.secondary" paragraph>
                    <strong>Impact:</strong> {chain.impact}
                  </Typography>
                  <List dense>
                    {chain.steps.map((step, stepIdx) => (
                      <ListItem key={stepIdx} sx={{ py: 0 }}>
                        <ListItemIcon sx={{ minWidth: 28 }}>
                          <Chip label={stepIdx + 1} size="small" sx={{ width: 20, height: 20, fontSize: "0.7rem" }} />
                        </ListItemIcon>
                        <ListItemText primary={step} />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              ))}
            </Box>
          )}

          {/* Recommendations */}
          {aiVulnScanResult.recommendations && aiVulnScanResult.recommendations.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Typography variant="h6" gutterBottom>
                📋 Recommendations
              </Typography>
              <List>
                {aiVulnScanResult.recommendations.map((item, idx) => (
                  <ListItem key={idx} sx={{ alignItems: "flex-start" }}>
                    <ListItemIcon>
                      <Chip label={idx + 1} size="small" color="primary" />
                    </ListItemIcon>
                    <ListItemText primary={item} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </Box>
      )}
    </Box>
  );
}

// Smali/Bytecode Viewer Component
function SmaliViewer({ smali }: { smali: import("../api/client").SmaliAnalysis }) {
  const theme = useTheme();
  const [selectedClass, setSelectedClass] = useState<string>("");
  const [selectedMethod, setSelectedMethod] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<"methods" | "classes">("methods");
  
  // Get class names from decompiled methods
  const classNames = [...new Set(smali.decompiled_methods.map(m => m.class_name))].sort();
  
  // Filter methods based on search and selected class
  const filteredMethods = smali.decompiled_methods.filter(method => {
    const matchesSearch = !searchQuery || 
      method.method_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      method.class_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      method.instructions.some(i => i.toLowerCase().includes(searchQuery.toLowerCase()));
    const matchesClass = !selectedClass || method.class_name === selectedClass;
    return matchesSearch && matchesClass;
  });
  
  // Get selected method's full code
  const currentMethod = selectedMethod 
    ? smali.decompiled_methods.find(m => `${m.class_name}.${m.method_name}${m.method_signature}` === selectedMethod)
    : null;
  
  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CodeIcon color="secondary" /> Smali Bytecode Decompilation
          <Chip 
            label={`${smali.statistics.total_methods_analyzed} methods`} 
            size="small" 
            color="secondary" 
          />
          <Chip 
            label={`${smali.statistics.classes_analyzed} classes`} 
            size="small" 
            variant="outlined"
          />
          {smali.interesting_methods.length > 0 && (
            <Chip 
              label={`${smali.interesting_methods.length} interesting`} 
              size="small" 
              color="warning"
            />
          )}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Grid container spacing={2}>
          {/* Stats Overview */}
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Methods</Typography>
            <Typography variant="h6">{smali.statistics.total_methods_analyzed}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Instructions</Typography>
            <Typography variant="h6">{smali.statistics.total_instructions.toLocaleString()}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Classes</Typography>
            <Typography variant="h6">{smali.statistics.classes_analyzed}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Native Methods</Typography>
            <Typography variant="h6">{smali.statistics.native_methods}</Typography>
          </Grid>
          <Grid item xs={6} sm={2}>
            <Typography variant="caption" color="text.secondary">Abstract</Typography>
            <Typography variant="h6">{smali.statistics.abstract_methods}</Typography>
          </Grid>
          
          {/* Search & Filter */}
          <Grid item xs={12}>
            <Divider sx={{ my: 2 }} />
            <Box sx={{ display: "flex", gap: 2, flexWrap: "wrap", alignItems: "center" }}>
              <TextField
                size="small"
                label="Search methods/classes"
                placeholder="e.g., onCreate, crypto, http"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                sx={{ minWidth: 250 }}
                InputProps={{
                  startAdornment: <SearchIcon sx={{ mr: 1, color: "text.secondary" }} />,
                }}
              />
              <Autocomplete
                size="small"
                options={classNames}
                value={selectedClass}
                onChange={(_, value) => setSelectedClass(value || "")}
                renderInput={(params) => (
                  <TextField {...params} label="Filter by class" placeholder="All classes" />
                )}
                sx={{ minWidth: 300 }}
              />
              <Chip 
                label={`${filteredMethods.length} methods shown`}
                size="small"
                variant="outlined"
              />
            </Box>
          </Grid>
          
          {/* Interesting Methods Highlight */}
          {smali.interesting_methods.length > 0 && (
            <Grid item xs={12}>
              <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.warning.main, 0.08) }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <WarningIcon color="warning" fontSize="small" />
                  Interesting Methods ({smali.interesting_methods.length})
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                  {smali.interesting_methods.slice(0, 15).map((method, idx) => (
                    <Tooltip 
                      key={idx} 
                      title={`${method.class}.${method.method} - ${method.pattern}`}
                    >
                      <Chip
                        label={`${method.method} (${method.pattern})`}
                        size="small"
                        color="warning"
                        variant="outlined"
                        onClick={() => {
                          setSelectedClass(method.class);
                          setSearchQuery(method.method);
                        }}
                        sx={{ cursor: "pointer" }}
                      />
                    </Tooltip>
                  ))}
                </Box>
              </Paper>
            </Grid>
          )}
          
          {/* Method List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ maxHeight: 500, overflow: "auto", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
              <List dense>
                {filteredMethods.slice(0, 100).map((method, idx) => {
                  const methodKey = `${method.class_name}.${method.method_name}${method.method_signature}`;
                  const isSelected = selectedMethod === methodKey;
                  return (
                    <ListItem
                      key={idx}
                      button
                      selected={isSelected}
                      onClick={() => setSelectedMethod(isSelected ? "" : methodKey)}
                      sx={{
                        borderLeft: isSelected ? `3px solid ${theme.palette.primary.main}` : "none",
                        "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.08) },
                      }}
                    >
                      <ListItemIcon sx={{ minWidth: 30 }}>
                        {method.is_native ? (
                          <Tooltip title="Native method"><CodeIcon fontSize="small" color="warning" /></Tooltip>
                        ) : method.is_abstract ? (
                          <Tooltip title="Abstract method"><CodeIcon fontSize="small" color="disabled" /></Tooltip>
                        ) : (
                          <FunctionIcon fontSize="small" color="primary" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={method.method_name}
                        secondary={
                          <Typography variant="caption" color="text.secondary" noWrap>
                            {method.class_name.split('.').pop()} • {method.instruction_count} inst
                          </Typography>
                        }
                        primaryTypographyProps={{ noWrap: true, variant: "body2" }}
                      />
                      {method.has_try_catch && (
                        <Chip label="try" size="small" sx={{ height: 18, fontSize: 10 }} />
                      )}
                    </ListItem>
                  );
                })}
                {filteredMethods.length > 100 && (
                  <ListItem>
                    <ListItemText 
                      primary={`... and ${filteredMethods.length - 100} more methods`}
                      primaryTypographyProps={{ color: "text.secondary", variant: "caption" }}
                    />
                  </ListItem>
                )}
              </List>
            </Paper>
          </Grid>
          
          {/* Code Viewer */}
          <Grid item xs={12} md={8}>
            <Paper 
              sx={{ 
                p: 2, 
                bgcolor: "#1e1e1e", 
                minHeight: 400,
                maxHeight: 500,
                overflow: "auto",
              }}
            >
              {currentMethod ? (
                <>
                  <Box sx={{ mb: 2, display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
                    <Box>
                      <Typography variant="subtitle2" color="primary.light">
                        {currentMethod.class_name}
                      </Typography>
                      <Typography variant="body2" color="grey.300" fontFamily="monospace">
                        {currentMethod.access_flags} {currentMethod.method_name}({currentMethod.parameters.join(", ")}) → {currentMethod.return_type}
                      </Typography>
                      <Typography variant="caption" color="grey.500">
                        {currentMethod.registers_count} registers • {currentMethod.instruction_count} instructions
                        {currentMethod.has_try_catch && " • has try-catch"}
                      </Typography>
                    </Box>
                    <Chip 
                      label={currentMethod.is_native ? "native" : currentMethod.is_abstract ? "abstract" : "bytecode"}
                      size="small"
                      color={currentMethod.is_native ? "warning" : currentMethod.is_abstract ? "default" : "success"}
                      variant="outlined"
                    />
                  </Box>
                  <Divider sx={{ borderColor: "grey.800", mb: 2 }} />
                  <Box 
                    component="pre" 
                    sx={{ 
                      m: 0, 
                      fontFamily: "'Fira Code', 'Consolas', monospace",
                      fontSize: 12,
                      lineHeight: 1.6,
                      color: "#d4d4d4",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-all",
                    }}
                  >
                    {currentMethod.instructions.length > 0 ? (
                      currentMethod.instructions.map((inst, idx) => {
                        // Syntax highlighting
                        let color = "#d4d4d4";
                        if (inst.includes("invoke-")) color = "#dcdcaa"; // Yellow for invokes
                        else if (inst.includes("const")) color = "#b5cea8"; // Green for constants
                        else if (inst.includes("return")) color = "#c586c0"; // Purple for returns
                        else if (inst.includes("if-") || inst.includes("goto")) color = "#569cd6"; // Blue for branches
                        else if (inst.includes("move")) color = "#9cdcfe"; // Light blue for moves
                        else if (inst.trim().startsWith("#")) color = "#6a9955"; // Green for comments
                        
                        return (
                          <div key={idx} style={{ color }}>
                            <span style={{ color: "#858585", marginRight: 8, userSelect: "none" }}>
                              {String(idx).padStart(4, " ")}
                            </span>
                            {inst}
                          </div>
                        );
                      })
                    ) : (
                      <Typography variant="body2" color="grey.500" fontStyle="italic">
                        {currentMethod.is_native 
                          ? "Native method - no bytecode available" 
                          : currentMethod.is_abstract
                          ? "Abstract method - no implementation"
                          : "No instructions"}
                      </Typography>
                    )}
                  </Box>
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: 400, color: "grey.500" }}>
                  <Typography variant="body2">
                    Select a method from the list to view its Smali bytecode
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
          
          {/* Full Class View */}
          {selectedClass && smali.class_smali[selectedClass] && (
            <Grid item xs={12}>
              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="body2">
                    View Full Class: {selectedClass.split('.').pop()}
                  </Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Paper 
                    sx={{ 
                      p: 2, 
                      bgcolor: "#1e1e1e", 
                      maxHeight: 500,
                      overflow: "auto",
                    }}
                  >
                    <Box 
                      component="pre" 
                      sx={{ 
                        m: 0, 
                        fontFamily: "'Fira Code', 'Consolas', monospace",
                        fontSize: 11,
                        lineHeight: 1.5,
                        color: "#d4d4d4",
                        whiteSpace: "pre",
                      }}
                    >
                      {smali.class_smali[selectedClass]}
                    </Box>
                  </Paper>
                </AccordionDetails>
              </Accordion>
            </Grid>
          )}
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// AI-Assisted Code Explainer Component
function AICodeExplainer({ 
  sourceCode, 
  className,
  language = "java"
}: { 
  sourceCode: string; 
  className: string;
  language?: "java" | "smali" | "kotlin";
}) {
  const theme = useTheme();
  const [explanation, setExplanation] = useState<CodeExplanationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [focusArea, setFocusArea] = useState<"security" | "functionality" | "data_flow" | null>(null);
  const [beginnerMode, setBeginnerMode] = useState(false);

  const analyzeCode = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const request: CodeExplanationRequest = {
        source_code: sourceCode,
        class_name: className,
        language: language,
        focus_area: focusArea,
        beginner_mode: beginnerMode,
      };
      const response = await reverseEngineeringClient.explainCode(request);
      setExplanation(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to analyze code");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Box sx={{ mt: 2 }}>
      <Box sx={{ display: "flex", gap: 2, alignItems: "center", mb: 2, flexWrap: "wrap" }}>
        <Typography variant="subtitle2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <AiIcon color="primary" fontSize="small" /> AI Code Analysis
        </Typography>
        
        <Box sx={{ display: "flex", gap: 1 }}>
          {(["security", "functionality", "data_flow", null] as const).map((area) => (
            <Chip
              key={area || "general"}
              label={area ? area.replace("_", " ").toUpperCase() : "GENERAL"}
              size="small"
              variant={focusArea === area ? "filled" : "outlined"}
              color={focusArea === area ? "primary" : "default"}
              onClick={() => setFocusArea(area)}
            />
          ))}
        </Box>
        
        <FormControlLabel
          control={
            <Switch
              size="small"
              checked={beginnerMode}
              onChange={(e) => setBeginnerMode(e.target.checked)}
            />
          }
          label="Beginner Mode"
          sx={{ ml: "auto" }}
        />
        
        <Button
          variant="contained"
          size="small"
          onClick={analyzeCode}
          disabled={isLoading || !sourceCode}
          startIcon={isLoading ? <CircularProgress size={16} /> : <AiIcon />}
        >
          {isLoading ? "Analyzing..." : "Explain Code"}
        </Button>
      </Box>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {explanation && (
        <Box sx={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {/* Summary */}
          <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.primary.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom>
              <AiIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
              Summary
            </Typography>
            <Typography variant="body2">{explanation.summary}</Typography>
          </Paper>

          {/* Detailed Explanation */}
          <Accordion defaultExpanded>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="subtitle2">Detailed Explanation</Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                {explanation.detailed_explanation}
              </Typography>
            </AccordionDetails>
          </Accordion>

          {/* Security Concerns */}
          {explanation.security_concerns.length > 0 && (
            <Accordion defaultExpanded>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <SecurityIcon color="error" fontSize="small" />
                  Security Concerns ({explanation.security_concerns.length})
                </Typography>
              </AccordionSummary>
              <AccordionDetails>
                {explanation.security_concerns.map((concern, idx) => (
                  <Paper 
                    key={idx} 
                    sx={{ 
                      p: 2, 
                      mb: 1, 
                      borderLeft: `4px solid ${
                        concern.severity === "critical" ? "#dc2626" :
                        concern.severity === "high" ? "#ea580c" :
                        concern.severity === "medium" ? "#ca8a04" : "#22c55e"
                      }` 
                    }}
                  >
                    <Box sx={{ display: "flex", gap: 1, mb: 1 }}>
                      <Chip 
                        label={concern.severity.toUpperCase()} 
                        size="small"
                        sx={{
                          bgcolor: alpha(
                            concern.severity === "critical" ? "#dc2626" :
                            concern.severity === "high" ? "#ea580c" :
                            concern.severity === "medium" ? "#ca8a04" : "#22c55e",
                            0.2
                          ),
                        }}
                      />
                      {concern.location && (
                        <Chip label={concern.location} size="small" variant="outlined" />
                      )}
                    </Box>
                    <Typography variant="body2" fontWeight="medium" gutterBottom>
                      {concern.issue}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {concern.recommendation}
                    </Typography>
                  </Paper>
                ))}
              </AccordionDetails>
            </Accordion>
          )}

          {/* Data Flow Analysis */}
          {explanation.data_flow_analysis && (
            <Accordion>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle2">Data Flow Analysis</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Typography variant="body2" sx={{ whiteSpace: "pre-wrap" }}>
                  {explanation.data_flow_analysis}
                </Typography>
              </AccordionDetails>
            </Accordion>
          )}

          {/* Interesting Findings */}
          {explanation.interesting_findings.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>
                <LightbulbIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle", color: "warning.main" }} />
                Interesting Findings
              </Typography>
              <Box sx={{ display: "flex", flexWrap: "wrap", gap: 1 }}>
                {explanation.interesting_findings.map((finding, idx) => (
                  <Chip key={idx} label={finding} size="small" variant="outlined" />
                ))}
              </Box>
            </Paper>
          )}

          {/* Suggested Focus Points */}
          {explanation.suggested_focus_points.length > 0 && (
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
              <Typography variant="subtitle2" gutterBottom>
                <SearchIcon fontSize="small" sx={{ mr: 1, verticalAlign: "middle" }} />
                Suggested Focus Points
              </Typography>
              <List dense>
                {explanation.suggested_focus_points.map((point, idx) => (
                  <ListItem key={idx}>
                    <ListItemText primary={point} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}

          {/* Code Quality Notes */}
          {explanation.code_quality_notes.length > 0 && (
            <Paper sx={{ p: 2 }}>
              <Typography variant="subtitle2" gutterBottom>Code Quality Notes</Typography>
              <List dense>
                {explanation.code_quality_notes.map((note, idx) => (
                  <ListItem key={idx}>
                    <ListItemIcon sx={{ minWidth: 30 }}>
                      <InfoIcon fontSize="small" color="info" />
                    </ListItemIcon>
                    <ListItemText primary={note} primaryTypographyProps={{ variant: "body2" }} />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}
        </Box>
      )}
    </Box>
  );
}

// Dynamic Analysis / Frida Scripts Viewer Component
function FridaScriptsViewer({ dynamicAnalysis }: { dynamicAnalysis: import("../api/client").DynamicAnalysis }) {
  const theme = useTheme();
  const [selectedScript, setSelectedScript] = useState<string>("");
  const [copied, setCopied] = useState(false);
  const [downloadedScript, setDownloadedScript] = useState<string | null>(null);
  
  const handleCopyScript = async (scriptCode: string) => {
    try {
      await navigator.clipboard.writeText(scriptCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };
  
  const handleDownloadScript = (script: import("../api/client").FridaScript) => {
    const blob = new Blob([script.script_code], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${script.category}_${dynamicAnalysis.package_name.replace(/\./g, "_")}.js`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    setDownloadedScript(script.name);
    setTimeout(() => setDownloadedScript(null), 2000);
  };

  const currentScript = selectedScript 
    ? dynamicAnalysis.frida_scripts.find(s => s.name === selectedScript)
    : null;

  const getCategoryIcon = (category: string) => {
    switch (category) {
      case "ssl_bypass": return "🔓";
      case "root_bypass": return "🌱";
      case "crypto_hook": return "🔐";
      case "auth_hook": return "🔑";
      case "method_trace": return "📍";
      case "network_hook": return "🌐";
      case "combined": return "⚡";
      case "emulator_bypass": return "📱";
      case "debugger_bypass": return "🐛";
      case "tampering_bypass": return "🛡️";
      case "screenshot_bypass": return "📸";
      default: return "📜";
    }
  };
  
  const getCategoryColor = (category: string) => {
    switch (category) {
      case "ssl_bypass": return theme.palette.warning.main;
      case "root_bypass": return theme.palette.success.main;
      case "crypto_hook": return theme.palette.info.main;
      case "auth_hook": return theme.palette.secondary.main;
      case "method_trace": return theme.palette.primary.main;
      case "network_hook": return "#00bcd4";
      case "combined": return theme.palette.error.main;
      case "emulator_bypass": return "#9c27b0";
      case "debugger_bypass": return "#ff5722";
      case "tampering_bypass": return "#607d8b";
      case "screenshot_bypass": return "#795548";
      default: return theme.palette.grey[500];
    }
  };

  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <CodeIcon color="secondary" />
          Dynamic Analysis - Frida Scripts ({dynamicAnalysis.total_scripts} scripts generated)
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Detection Summary */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Typography variant="subtitle2" gutterBottom>Detection Summary</Typography>
          <Grid container spacing={1}>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.ssl_pinning_detected ? "✅" : "❌"}</span>}
                label="SSL Pinning"
                color={dynamicAnalysis.ssl_pinning_detected ? "warning" : "default"}
                variant={dynamicAnalysis.ssl_pinning_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.root_detection_detected ? "✅" : "❌"}</span>}
                label="Root Detection"
                color={dynamicAnalysis.root_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.root_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.emulator_detection_detected ? "✅" : "❌"}</span>}
                label="Emulator Check"
                color={dynamicAnalysis.emulator_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.emulator_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.debugger_detection_detected ? "✅" : "❌"}</span>}
                label="Debugger Check"
                color={dynamicAnalysis.debugger_detection_detected ? "warning" : "default"}
                variant={dynamicAnalysis.debugger_detection_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>{dynamicAnalysis.anti_tampering_detected ? "✅" : "❌"}</span>}
                label="Anti-Tamper"
                color={dynamicAnalysis.anti_tampering_detected ? "warning" : "default"}
                variant={dynamicAnalysis.anti_tampering_detected ? "filled" : "outlined"}
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                icon={<span>🔐</span>}
                label={`${dynamicAnalysis.crypto_methods.length} Crypto`}
                color={dynamicAnalysis.crypto_methods.length > 0 ? "info" : "default"}
                variant="outlined"
                size="small"
                sx={{ width: "100%" }}
              />
            </Grid>
          </Grid>
          
          {/* Commands */}
          <Box sx={{ mt: 2 }}>
            <Typography variant="caption" color="text.secondary">Frida Commands:</Typography>
            <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap", mt: 0.5 }}>
              <Chip
                label={dynamicAnalysis.frida_spawn_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10 }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_spawn_command)}
              />
              <Chip
                label={dynamicAnalysis.frida_attach_command}
                size="small"
                sx={{ fontFamily: "monospace", fontSize: 10 }}
                onClick={() => handleCopyScript(dynamicAnalysis.frida_attach_command)}
              />
            </Box>
          </Box>
        </Paper>
        
        <Grid container spacing={2}>
          {/* Script List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 1, maxHeight: 500, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
                Available Scripts
              </Typography>
              <List dense>
                {dynamicAnalysis.frida_scripts.map((script) => (
                  <ListItem
                    key={script.name}
                    sx={{
                      cursor: "pointer",
                      bgcolor: selectedScript === script.name 
                        ? alpha(getCategoryColor(script.category), 0.15)
                        : "transparent",
                      borderLeft: selectedScript === script.name 
                        ? `3px solid ${getCategoryColor(script.category)}`
                        : "3px solid transparent",
                      "&:hover": {
                        bgcolor: alpha(getCategoryColor(script.category), 0.08),
                      },
                      borderRadius: 1,
                      mb: 0.5,
                    }}
                    onClick={() => setSelectedScript(script.name)}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          <span>{getCategoryIcon(script.category)}</span>
                          <Typography variant="body2" sx={{ fontWeight: selectedScript === script.name ? 600 : 400 }}>
                            {script.name}
                          </Typography>
                          {script.is_dangerous && (
                            <Chip label="Modifies Behavior" size="small" color="error" sx={{ height: 18, fontSize: 9 }} />
                          )}
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary" sx={{ fontSize: 10 }}>
                          {script.description.substring(0, 60)}...
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
          
          {/* Script Viewer */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ bgcolor: "#1e1e1e", height: 500, display: "flex", flexDirection: "column" }}>
              {currentScript ? (
                <>
                  {/* Script Header */}
                  <Box sx={{ 
                    p: 1.5, 
                    borderBottom: "1px solid #333",
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center"
                  }}>
                    <Box>
                      <Typography variant="subtitle2" sx={{ color: "#fff", display: "flex", alignItems: "center", gap: 1 }}>
                        {getCategoryIcon(currentScript.category)} {currentScript.name}
                      </Typography>
                      <Typography variant="caption" sx={{ color: "#888" }}>
                        {currentScript.description}
                      </Typography>
                    </Box>
                    <Box sx={{ display: "flex", gap: 1 }}>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={copied ? <CheckIcon /> : <CopyIcon />}
                        onClick={() => handleCopyScript(currentScript.script_code)}
                        sx={{ 
                          color: copied ? "#4caf50" : "#fff", 
                          borderColor: copied ? "#4caf50" : "#555",
                          fontSize: 11,
                        }}
                      >
                        {copied ? "Copied!" : "Copy"}
                      </Button>
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={downloadedScript === currentScript.name ? <CheckIcon /> : <DownloadIcon />}
                        onClick={() => handleDownloadScript(currentScript)}
                        sx={{ fontSize: 11 }}
                        color={downloadedScript === currentScript.name ? "success" : "primary"}
                      >
                        {downloadedScript === currentScript.name ? "Downloaded!" : "Download .js"}
                      </Button>
                    </Box>
                  </Box>
                  
                  {/* Usage Instructions */}
                  <Box sx={{ px: 2, py: 1, bgcolor: "#252526", borderBottom: "1px solid #333" }}>
                    <Typography variant="caption" sx={{ color: "#569cd6" }}>
                      Usage: <code style={{ color: "#ce9178" }}>{currentScript.usage_instructions}</code>
                    </Typography>
                  </Box>
                  
                  {/* Script Code */}
                  <Box sx={{ flex: 1, overflow: "auto", p: 2 }}>
                    <Box
                      component="pre"
                      sx={{
                        m: 0,
                        fontFamily: "'Fira Code', 'Consolas', monospace",
                        fontSize: 11,
                        lineHeight: 1.5,
                        color: "#d4d4d4",
                        whiteSpace: "pre",
                      }}
                    >
                      {currentScript.script_code.split('\n').map((line, idx) => {
                        // Basic JavaScript syntax highlighting
                        let highlighted = line;
                        
                        // Comments
                        if (line.trim().startsWith('//')) {
                          highlighted = `<span style="color: #6a9955">${line}</span>`;
                        }
                        // Strings
                        else {
                          highlighted = line
                            .replace(/(["'])((?:(?!\1)[^\\]|\\.)*)(\1)/g, '<span style="color: #ce9178">$1$2$3</span>')
                            .replace(/\b(function|var|let|const|return|if|else|try|catch|for|while|true|false|null|undefined|this|new)\b/g, '<span style="color: #569cd6">$1</span>')
                            .replace(/\b(console)\.(log|warn|error)/g, '<span style="color: #dcdcaa">$1</span>.<span style="color: #dcdcaa">$2</span>')
                            .replace(/\b(Java)\.(use|perform|registerClass|cast|enumerateLoadedClasses)/g, '<span style="color: #4ec9b0">$1</span>.<span style="color: #dcdcaa">$2</span>')
                            .replace(/\.implementation/g, '.<span style="color: #9cdcfe">implementation</span>');
                        }
                        
                        return (
                          <Box 
                            key={idx} 
                            component="span" 
                            sx={{ display: "block" }}
                            dangerouslySetInnerHTML={{ __html: highlighted }}
                          />
                        );
                      })}
                    </Box>
                  </Box>
                  
                  {/* Target Info */}
                  <Box sx={{ 
                    px: 2, 
                    py: 1, 
                    bgcolor: "#252526",
                    borderTop: "1px solid #333",
                    display: "flex",
                    gap: 2,
                    flexWrap: "wrap"
                  }}>
                    <Typography variant="caption" sx={{ color: "#888" }}>
                      <strong style={{ color: "#569cd6" }}>Target Classes:</strong>{" "}
                      {currentScript.target_classes.slice(0, 3).join(", ")}
                      {currentScript.target_classes.length > 3 && ` +${currentScript.target_classes.length - 3} more`}
                    </Typography>
                  </Box>
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "#888" }}>
                  <Typography variant="body2">
                    Select a script from the list to view and download
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
        
        {/* Suggested Test Cases */}
        {dynamicAnalysis.suggested_test_cases.length > 0 && (
          <Paper sx={{ p: 2, mt: 2, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
            <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <span>📋</span> Suggested Test Cases
            </Typography>
            <List dense>
              {dynamicAnalysis.suggested_test_cases.map((testCase, idx) => (
                <ListItem key={idx} sx={{ py: 0.25 }}>
                  <ListItemText
                    primary={
                      <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span style={{ color: theme.palette.primary.main }}>•</span>
                        {testCase}
                      </Typography>
                    }
                  />
                </ListItem>
              ))}
            </List>
          </Paper>
        )}
        
        {/* Crypto Methods Found */}
        {dynamicAnalysis.crypto_methods.length > 0 && (
          <Accordion sx={{ mt: 2 }}>
            <AccordionSummary expandIcon={<ExpandMoreIcon />}>
              <Typography variant="body2">
                🔐 Cryptographic Operations Detected ({dynamicAnalysis.crypto_methods.length})
              </Typography>
            </AccordionSummary>
            <AccordionDetails>
              <Grid container spacing={1}>
                {dynamicAnalysis.crypto_methods.map((method, idx) => (
                  <Grid item xs={12} sm={6} key={idx}>
                    <Paper sx={{ p: 1.5, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
                      <Typography variant="subtitle2">{method.pattern}</Typography>
                      <Typography variant="caption" color="text.secondary">{method.description}</Typography>
                      <Typography 
                        variant="caption" 
                        component="div" 
                        sx={{ 
                          fontFamily: "monospace", 
                          mt: 0.5, 
                          p: 0.5, 
                          bgcolor: "rgba(0,0,0,0.2)", 
                          borderRadius: 0.5,
                          fontSize: 10,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap"
                        }}
                      >
                        {method.context}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </AccordionDetails>
          </Accordion>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// Native Library Analysis Viewer Component
function NativeLibraryViewer({ nativeAnalysis }: { nativeAnalysis: import("../api/client").NativeAnalysisResult }) {
  const theme = useTheme();
  const [selectedLib, setSelectedLib] = useState<string>("");
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "critical": return theme.palette.error.main;
      case "high": return theme.palette.warning.main;
      case "medium": return theme.palette.info.main;
      default: return theme.palette.success.main;
    }
  };

  const currentLib = selectedLib 
    ? nativeAnalysis.libraries.find(l => l.name === selectedLib)
    : null;

  return (
    <Accordion defaultExpanded={false}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <span>⚙️</span> Native Library Analysis
          <Chip label={`${nativeAnalysis.total_libraries} libraries`} size="small" />
          <Chip 
            label={nativeAnalysis.risk_level.toUpperCase()} 
            size="small" 
            sx={{ 
              bgcolor: alpha(getRiskColor(nativeAnalysis.risk_level), 0.2),
              color: getRiskColor(nativeAnalysis.risk_level),
              fontWeight: 600,
            }}
          />
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Summary Stats */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Libraries</Typography>
              <Typography variant="h6">{nativeAnalysis.total_libraries}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Architectures</Typography>
              <Typography variant="body2">{nativeAnalysis.architectures.join(", ") || "N/A"}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">JNI Functions</Typography>
              <Typography variant="h6">{nativeAnalysis.total_jni_functions}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Suspicious</Typography>
              <Typography variant="h6" color="warning.main">{nativeAnalysis.total_suspicious_functions}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Chip
                icon={<span>{nativeAnalysis.has_native_anti_debug ? "🛡️" : "✓"}</span>}
                label="Anti-Debug"
                color={nativeAnalysis.has_native_anti_debug ? "warning" : "default"}
                size="small"
              />
            </Grid>
            <Grid item xs={6} sm={2}>
              <Chip
                icon={<span>{nativeAnalysis.has_native_crypto ? "🔐" : "✓"}</span>}
                label="Native Crypto"
                color={nativeAnalysis.has_native_crypto ? "info" : "default"}
                size="small"
              />
            </Grid>
          </Grid>
          {nativeAnalysis.summary && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {nativeAnalysis.summary}
            </Typography>
          )}
        </Paper>

        {/* Native Secrets Found */}
        {nativeAnalysis.native_secrets && nativeAnalysis.native_secrets.length > 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <Typography variant="subtitle2" gutterBottom>
              ⚠️ {nativeAnalysis.native_secrets.length} Potential Secrets Found in Native Code
            </Typography>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 1 }}>
              {nativeAnalysis.native_secrets.slice(0, 10).map((secret, idx) => (
                <Chip 
                  key={idx} 
                  label={secret.length > 30 ? secret.substring(0, 30) + "..." : secret} 
                  size="small" 
                  sx={{ fontFamily: "monospace", fontSize: 10 }}
                />
              ))}
              {nativeAnalysis.native_secrets.length > 10 && (
                <Chip label={`+${nativeAnalysis.native_secrets.length - 10} more`} size="small" variant="outlined" />
              )}
            </Box>
          </Alert>
        )}

        <Grid container spacing={2}>
          {/* Library List */}
          <Grid item xs={12} md={4}>
            <Paper sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
              <Typography variant="subtitle2" sx={{ px: 1, py: 0.5 }}>
                Native Libraries ({nativeAnalysis.libraries.length})
              </Typography>
              <List dense>
                {nativeAnalysis.libraries.map((lib) => (
                  <ListItem
                    key={lib.name}
                    sx={{
                      cursor: "pointer",
                      bgcolor: selectedLib === lib.name 
                        ? alpha(theme.palette.primary.main, 0.1)
                        : "transparent",
                      borderLeft: selectedLib === lib.name 
                        ? `3px solid ${theme.palette.primary.main}`
                        : "3px solid transparent",
                      "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                      borderRadius: 1,
                      mb: 0.5,
                    }}
                    onClick={() => setSelectedLib(lib.name)}
                  >
                    <ListItemText
                      primary={
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {lib.name}
                          </Typography>
                          {lib.has_anti_debug && <span title="Anti-Debug">🛡️</span>}
                          {lib.has_crypto && <span title="Crypto">🔐</span>}
                          {lib.has_jni && <span title="JNI">☕</span>}
                        </Box>
                      }
                      secondary={
                        <Typography variant="caption" color="text.secondary">
                          {lib.architecture} • {(lib.size / 1024).toFixed(1)} KB
                          {lib.is_stripped && " • stripped"}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>

          {/* Library Details */}
          <Grid item xs={12} md={8}>
            <Paper sx={{ p: 2, minHeight: 400, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
              {currentLib ? (
                <>
                  <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <span>📚</span> {currentLib.name}
                  </Typography>
                  
                  <Grid container spacing={1} sx={{ mb: 2 }}>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Architecture</Typography>
                      <Typography variant="body2">{currentLib.architecture}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Size</Typography>
                      <Typography variant="body2">{(currentLib.size / 1024).toFixed(2)} KB</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Stripped</Typography>
                      <Typography variant="body2">{currentLib.is_stripped ? "Yes" : "No"}</Typography>
                    </Grid>
                    <Grid item xs={6} sm={3}>
                      <Typography variant="caption" color="text.secondary">Functions</Typography>
                      <Typography variant="body2">{currentLib.functions?.length || 0}</Typography>
                    </Grid>
                  </Grid>

                  {/* JNI Functions */}
                  {currentLib.jni_functions && currentLib.jni_functions.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        ☕ JNI Functions ({currentLib.jni_functions.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.jni_functions.slice(0, 15).map((fn, idx) => (
                          <Chip 
                            key={idx}
                            label={fn.name}
                            size="small"
                            color="primary"
                            variant="outlined"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                        {currentLib.jni_functions.length > 15 && (
                          <Chip label={`+${currentLib.jni_functions.length - 15} more`} size="small" />
                        )}
                      </Box>
                    </Box>
                  )}

                  {/* Anti-Debug Indicators */}
                  {currentLib.anti_debug_indicators && currentLib.anti_debug_indicators.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom color="warning.main">
                        🛡️ Anti-Debug Indicators ({currentLib.anti_debug_indicators.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.anti_debug_indicators.map((indicator, idx) => (
                          <Chip 
                            key={idx}
                            label={indicator}
                            size="small"
                            color="warning"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {/* Crypto Indicators */}
                  {currentLib.crypto_indicators && currentLib.crypto_indicators.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom color="info.main">
                        🔐 Crypto Functions ({currentLib.crypto_indicators.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
                        {currentLib.crypto_indicators.slice(0, 10).map((indicator, idx) => (
                          <Chip 
                            key={idx}
                            label={indicator}
                            size="small"
                            color="info"
                            variant="outlined"
                            sx={{ fontFamily: "monospace", fontSize: 10 }}
                          />
                        ))}
                      </Box>
                    </Box>
                  )}

                  {/* URLs Found */}
                  {currentLib.urls_found && currentLib.urls_found.length > 0 && (
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="subtitle2" gutterBottom>
                        🌐 URLs Found ({currentLib.urls_found.length})
                      </Typography>
                      <List dense sx={{ maxHeight: 100, overflow: "auto" }}>
                        {currentLib.urls_found.slice(0, 10).map((url, idx) => (
                          <ListItem key={idx} sx={{ py: 0 }}>
                            <ListItemText 
                              primary={<Typography variant="caption" fontFamily="monospace">{url}</Typography>}
                            />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {/* Secrets Found */}
                  {currentLib.secrets_found && currentLib.secrets_found.length > 0 && (
                    <Alert severity="error" sx={{ mt: 1 }}>
                      <Typography variant="subtitle2">
                        ⚠️ Potential Secrets Found ({currentLib.secrets_found.length})
                      </Typography>
                      <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                        {currentLib.secrets_found.slice(0, 5).map((secret, idx) => (
                          <Chip 
                            key={idx}
                            label={secret.length > 40 ? secret.substring(0, 40) + "..." : secret}
                            size="small"
                            color="error"
                            sx={{ fontFamily: "monospace", fontSize: 9 }}
                          />
                        ))}
                      </Box>
                    </Alert>
                  )}
                </>
              ) : (
                <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 200 }}>
                  <Typography variant="body2" color="text.secondary">
                    Select a library to view details
                  </Typography>
                </Box>
              )}
            </Paper>
          </Grid>
        </Grid>
      </AccordionDetails>
    </Accordion>
  );
}

// ============================================================================
// Data Flow / Taint Analysis Viewer
// ============================================================================

function DataFlowAnalysisViewer({ dataFlowAnalysis }: { dataFlowAnalysis: DataFlowAnalysisResult }) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0);
  const [selectedFlow, setSelectedFlow] = useState<number | null>(null);

  const getSeverityColor = (severity: string): string => {
    switch (severity.toLowerCase()) {
      case "critical": return theme.palette.error.main;
      case "high": return "#ea580c";
      case "medium": return theme.palette.warning.main;
      case "low": return theme.palette.success.main;
      default: return theme.palette.grey[500];
    }
  };

  const getSourceIcon = (sourceType: string): string => {
    switch (sourceType) {
      case "location": return "📍";
      case "device_info": return "📱";
      case "contacts": return "👥";
      case "sms": return "💬";
      case "accounts": return "🔑";
      case "clipboard": return "📋";
      case "media": return "🖼️";
      case "file_system": return "📁";
      case "network_response": return "🌐";
      case "crypto": return "🔐";
      default: return "📥";
    }
  };

  const getSinkIcon = (sinkType: string): string => {
    switch (sinkType) {
      case "network": return "🌍";
      case "storage": return "💾";
      case "logging": return "📝";
      case "ipc": return "🔗";
      case "sms_send": return "📤";
      case "external_storage": return "📂";
      case "process_execution": return "⚙️";
      case "reflection": return "🔄";
      case "native": return "🔧";
      default: return "📤";
    }
  };

  return (
    <Accordion defaultExpanded={dataFlowAnalysis.critical_flows > 0 || dataFlowAnalysis.high_risk_flows > 0}>
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <span>🔀</span> Data Flow Analysis
          <Chip label={`${dataFlowAnalysis.total_flows} flows`} size="small" />
          {dataFlowAnalysis.critical_flows > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.critical_flows} critical`} 
              size="small" 
              sx={{ 
                bgcolor: alpha(theme.palette.error.main, 0.2),
                color: theme.palette.error.main,
                fontWeight: 600,
              }}
            />
          )}
          {dataFlowAnalysis.high_risk_flows > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.high_risk_flows} high`} 
              size="small" 
              sx={{ 
                bgcolor: alpha("#ea580c", 0.2),
                color: "#ea580c",
                fontWeight: 600,
              }}
            />
          )}
          {dataFlowAnalysis.privacy_violations.length > 0 && (
            <Chip 
              label={`${dataFlowAnalysis.privacy_violations.length} privacy issues`} 
              size="small" 
              color="warning"
            />
          )}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        {/* Summary Stats */}
        <Paper sx={{ p: 2, mb: 2, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
          <Grid container spacing={2}>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Sources Found</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_sources}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Sinks Found</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_sinks}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Data Flows</Typography>
              <Typography variant="h6">{dataFlowAnalysis.total_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Critical</Typography>
              <Typography variant="h6" color="error.main">{dataFlowAnalysis.critical_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">High Risk</Typography>
              <Typography variant="h6" sx={{ color: "#ea580c" }}>{dataFlowAnalysis.high_risk_flows}</Typography>
            </Grid>
            <Grid item xs={6} sm={2}>
              <Typography variant="caption" color="text.secondary">Privacy Violations</Typography>
              <Typography variant="h6" color="warning.main">{dataFlowAnalysis.privacy_violations.length}</Typography>
            </Grid>
          </Grid>
          {dataFlowAnalysis.summary && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              {dataFlowAnalysis.summary}
            </Typography>
          )}
        </Paper>

        {/* Tabs for different views */}
        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 2 }}>
          <Tab label="Data Flow Paths" />
          <Tab label={`Sources (${dataFlowAnalysis.sources_found.length})`} />
          <Tab label={`Sinks (${dataFlowAnalysis.sinks_found.length})`} />
          <Tab label="Privacy & Recommendations" />
        </Tabs>

        {/* Tab 0: Data Flow Paths */}
        {activeTab === 0 && (
          <Grid container spacing={2}>
            {/* Flow List */}
            <Grid item xs={12} md={5}>
              <Paper sx={{ p: 1, maxHeight: 400, overflow: "auto" }}>
                <Typography variant="subtitle2" sx={{ px: 1, py: 0.5, display: "flex", alignItems: "center", gap: 1 }}>
                  🔀 Data Flow Paths ({dataFlowAnalysis.data_flow_paths.length})
                </Typography>
                {dataFlowAnalysis.data_flow_paths.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="text.secondary">
                      ✅ No problematic data flows detected
                    </Typography>
                  </Box>
                ) : (
                  <List dense>
                    {dataFlowAnalysis.data_flow_paths.map((flow, idx) => (
                      <ListItem
                        key={idx}
                        sx={{
                          cursor: "pointer",
                          bgcolor: selectedFlow === idx 
                            ? alpha(theme.palette.primary.main, 0.1)
                            : "transparent",
                          borderLeft: `3px solid ${getSeverityColor(flow.severity)}`,
                          "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
                          borderRadius: 1,
                          mb: 0.5,
                          flexDirection: "column",
                          alignItems: "flex-start",
                        }}
                        onClick={() => setSelectedFlow(idx)}
                      >
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                          <span>{getSourceIcon(flow.source.source_type)}</span>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {flow.source.source_type}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">→</Typography>
                          <span>{getSinkIcon(flow.sink.sink_type)}</span>
                          <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 11 }}>
                            {flow.sink.sink_type}
                          </Typography>
                          <Box sx={{ flexGrow: 1 }} />
                          <Chip 
                            label={flow.severity} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(flow.severity), 0.2),
                              color: getSeverityColor(flow.severity),
                              fontWeight: 600,
                              fontSize: 9,
                              height: 18,
                            }}
                          />
                        </Box>
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                          {flow.affected_class.split("/").pop()}.{flow.affected_method.split("(")[0]}
                        </Typography>
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Flow Details */}
            <Grid item xs={12} md={7}>
              <Paper sx={{ p: 2, minHeight: 400, bgcolor: alpha(theme.palette.background.paper, 0.5) }}>
                {selectedFlow !== null && dataFlowAnalysis.data_flow_paths[selectedFlow] ? (
                  (() => {
                    const flow = dataFlowAnalysis.data_flow_paths[selectedFlow];
                    return (
                      <>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 2 }}>
                          <Chip 
                            label={flow.severity.toUpperCase()} 
                            size="small" 
                            sx={{ 
                              bgcolor: alpha(getSeverityColor(flow.severity), 0.2),
                              color: getSeverityColor(flow.severity),
                              fontWeight: 600,
                            }}
                          />
                          {flow.is_privacy_violation && (
                            <Chip label="Privacy Issue" size="small" color="warning" />
                          )}
                          {flow.gdpr_relevant && (
                            <Chip label="GDPR Relevant" size="small" color="error" variant="outlined" />
                          )}
                          <Chip label={flow.owasp_category} size="small" variant="outlined" />
                        </Box>

                        <Typography variant="subtitle2" gutterBottom>📍 Source (Data Origin)</Typography>
                        <Paper sx={{ p: 1.5, mb: 2, bgcolor: alpha(theme.palette.info.main, 0.05), border: `1px solid ${alpha(theme.palette.info.main, 0.3)}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <span style={{ fontSize: 20 }}>{getSourceIcon(flow.source.source_type)}</span>
                            <Typography variant="subtitle2">{flow.source.source_type}</Typography>
                            <Chip 
                              label={flow.source.sensitivity} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(getSeverityColor(flow.source.sensitivity), 0.2),
                                color: getSeverityColor(flow.source.sensitivity),
                                fontSize: 10,
                              }}
                            />
                          </Box>
                          <Typography variant="caption" display="block" fontFamily="monospace">
                            {flow.source.class_name.split("/").pop()}.{flow.source.method_name}()
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                            {flow.source.description}
                          </Typography>
                        </Paper>

                        <Typography variant="subtitle2" gutterBottom>📤 Sink (Data Destination)</Typography>
                        <Paper sx={{ p: 1.5, mb: 2, bgcolor: alpha(theme.palette.error.main, 0.05), border: `1px solid ${alpha(theme.palette.error.main, 0.3)}` }}>
                          <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 1 }}>
                            <span style={{ fontSize: 20 }}>{getSinkIcon(flow.sink.sink_type)}</span>
                            <Typography variant="subtitle2">{flow.sink.sink_type}</Typography>
                            <Chip 
                              label={flow.sink.risk_level} 
                              size="small" 
                              sx={{ 
                                bgcolor: alpha(getSeverityColor(flow.sink.risk_level), 0.2),
                                color: getSeverityColor(flow.sink.risk_level),
                                fontSize: 10,
                              }}
                            />
                          </Box>
                          <Typography variant="caption" display="block" fontFamily="monospace">
                            {flow.sink.class_name.split("/").pop()}.{flow.sink.method_name}()
                          </Typography>
                          <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                            {flow.sink.description}
                          </Typography>
                        </Paper>

                        <Typography variant="subtitle2" gutterBottom>📍 Location</Typography>
                        <Typography variant="caption" fontFamily="monospace" display="block" sx={{ mb: 2 }}>
                          {flow.affected_class}
                          <br />
                          Method: {flow.affected_method}
                        </Typography>

                        <Typography variant="subtitle2" gutterBottom>📝 Description</Typography>
                        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                          {flow.description}
                        </Typography>

                        <Alert severity="info" sx={{ mt: 1 }}>
                          <Typography variant="subtitle2" gutterBottom>💡 Recommendation</Typography>
                          <Typography variant="body2">
                            {flow.recommendation}
                          </Typography>
                        </Alert>
                      </>
                    );
                  })()
                ) : (
                  <Box sx={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", minHeight: 200 }}>
                    <Typography variant="body2" color="text.secondary">
                      Select a data flow to view details
                    </Typography>
                  </Box>
                )}
              </Paper>
            </Grid>
          </Grid>
        )}

        {/* Tab 1: Sources */}
        {activeTab === 1 && (
          <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>API Call</TableCell>
                  <TableCell>Sensitivity</TableCell>
                  <TableCell>Location</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataFlowAnalysis.sources_found.map((source, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span>{getSourceIcon(source.source_type)}</span>
                        <Typography variant="body2">{source.source_type}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {source.class_name.split("/").pop()}.{source.method_name}()
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={source.sensitivity} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(getSeverityColor(source.sensitivity), 0.2),
                          color: getSeverityColor(source.sensitivity),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {source.affected_method}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
                {dataFlowAnalysis.sources_found.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No sensitive data sources detected
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Tab 2: Sinks */}
        {activeTab === 2 && (
          <TableContainer component={Paper} sx={{ maxHeight: 400 }}>
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell>Type</TableCell>
                  <TableCell>API Call</TableCell>
                  <TableCell>Risk Level</TableCell>
                  <TableCell>Location</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {dataFlowAnalysis.sinks_found.map((sink, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                        <span>{getSinkIcon(sink.sink_type)}</span>
                        <Typography variant="body2">{sink.sink_type}</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {sink.class_name.split("/").pop()}.{sink.method_name}()
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={sink.risk_level} 
                        size="small" 
                        sx={{ 
                          bgcolor: alpha(getSeverityColor(sink.risk_level), 0.2),
                          color: getSeverityColor(sink.risk_level),
                          fontWeight: 600,
                        }}
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="caption" fontFamily="monospace">
                        {sink.affected_method}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
                {dataFlowAnalysis.sinks_found.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={4} align="center">
                      <Typography variant="body2" color="text.secondary">
                        No data sinks detected
                      </Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        )}

        {/* Tab 3: Privacy & Recommendations */}
        {activeTab === 3 && (
          <Grid container spacing={2}>
            {/* Privacy Violations */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%" }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>🔒</span> Privacy Violations ({dataFlowAnalysis.privacy_violations.length})
                </Typography>
                {dataFlowAnalysis.privacy_violations.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="success.main">
                      ✅ No privacy violations detected
                    </Typography>
                  </Box>
                ) : (
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dataFlowAnalysis.privacy_violations.map((violation, idx) => (
                      <ListItem key={idx} sx={{ 
                        flexDirection: "column", 
                        alignItems: "flex-start",
                        bgcolor: alpha(theme.palette.warning.main, 0.05),
                        borderRadius: 1,
                        mb: 1,
                        border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                      }}>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1, width: "100%" }}>
                          <Chip label={violation.data_type} size="small" color="warning" />
                          <Typography variant="caption" fontFamily="monospace">
                            {violation.source} → {violation.sink}
                          </Typography>
                        </Box>
                        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                          {violation.description}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {violation.affected_class.split("/").pop()}.{violation.affected_method}
                        </Typography>
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Recommendations */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2, height: "100%" }}>
                <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <span>💡</span> Recommendations
                </Typography>
                {dataFlowAnalysis.recommendations.length === 0 ? (
                  <Box sx={{ p: 2, textAlign: "center" }}>
                    <Typography variant="body2" color="success.main">
                      ✅ No recommendations at this time
                    </Typography>
                  </Box>
                ) : (
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dataFlowAnalysis.recommendations.map((rec, idx) => (
                      <ListItem key={idx}>
                        <ListItemIcon sx={{ minWidth: 30 }}>
                          <InfoIcon color="info" fontSize="small" />
                        </ListItemIcon>
                        <ListItemText 
                          primary={rec}
                          primaryTypographyProps={{ variant: "body2" }}
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>
            </Grid>

            {/* Data Leak Risks */}
            {dataFlowAnalysis.data_leak_risks.length > 0 && (
              <Grid item xs={12}>
                <Alert severity="error">
                  <Typography variant="subtitle2" gutterBottom>
                    ⚠️ Data Leak Risks ({dataFlowAnalysis.data_leak_risks.length})
                  </Typography>
                  <List dense>
                    {dataFlowAnalysis.data_leak_risks.slice(0, 5).map((risk, idx) => (
                      <ListItem key={idx} sx={{ py: 0 }}>
                        <ListItemText
                          primary={
                            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                              <Chip 
                                label={risk.severity} 
                                size="small" 
                                sx={{ 
                                  bgcolor: alpha(getSeverityColor(risk.severity), 0.2),
                                  color: getSeverityColor(risk.severity),
                                  fontSize: 10,
                                }}
                              />
                              <Typography variant="body2">{risk.description}</Typography>
                            </Box>
                          }
                          secondary={`${risk.source} → ${risk.sink}`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Alert>
              </Grid>
            )}
          </Grid>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

// Hardening Score Card Component
function HardeningScoreCard({ hardeningScore }: { hardeningScore: import("../api/client").HardeningScore }) {
  const theme = useTheme();
  
  const getGradeColor = (grade: string) => {
    switch (grade) {
      case "A": return theme.palette.success.main;
      case "B": return theme.palette.success.light;
      case "C": return theme.palette.warning.main;
      case "D": return theme.palette.warning.dark;
      case "F": return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "low": return theme.palette.success.main;
      case "medium": return theme.palette.warning.main;
      case "high": return theme.palette.error.light;
      case "critical": return theme.palette.error.main;
      default: return theme.palette.grey[500];
    }
  };

  const categories = hardeningScore.categories;
  const categoryOrder = [
    { key: 'code_protection', name: 'Code Protection', icon: '🛡️' },
    { key: 'network_security', name: 'Network Security', icon: '🌐' },
    { key: 'data_storage', name: 'Data Storage', icon: '💾' },
    { key: 'authentication_crypto', name: 'Auth & Crypto', icon: '🔐' },
    { key: 'platform_security', name: 'Platform Security', icon: '📱' },
  ];

  return (
    <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <SecurityIcon color="primary" /> Security Hardening Score
      </Typography>

      <Grid container spacing={3}>
        {/* Main Score Display */}
        <Grid item xs={12} md={4}>
          <Box sx={{ 
            textAlign: "center", 
            p: 3, 
            borderRadius: 2, 
            bgcolor: alpha(getGradeColor(hardeningScore.grade), 0.1),
            border: `2px solid ${alpha(getGradeColor(hardeningScore.grade), 0.3)}`
          }}>
            <Typography 
              variant="h1" 
              sx={{ 
                fontWeight: 700, 
                color: getGradeColor(hardeningScore.grade),
                textShadow: `0 0 20px ${alpha(getGradeColor(hardeningScore.grade), 0.5)}`
              }}
            >
              {hardeningScore.grade}
            </Typography>
            <Typography variant="h4" sx={{ fontWeight: 600, mb: 1 }}>
              {hardeningScore.overall_score}/100
            </Typography>
            <Chip 
              label={hardeningScore.risk_level.toUpperCase()} 
              sx={{ 
                bgcolor: alpha(getRiskColor(hardeningScore.risk_level), 0.2),
                color: getRiskColor(hardeningScore.risk_level),
                fontWeight: 600,
              }}
            />
            
            {/* Comparison */}
            {hardeningScore.comparison && (
              <Box sx={{ mt: 2, pt: 2, borderTop: `1px solid ${alpha(theme.palette.divider, 0.3)}` }}>
                <Typography variant="caption" color="text.secondary">
                  Industry Avg: {hardeningScore.comparison.industry_average}
                </Typography>
                <Typography variant="body2">
                  Better than {hardeningScore.comparison.percentile}% of apps
                </Typography>
              </Box>
            )}
          </Box>
        </Grid>

        {/* Category Scores */}
        <Grid item xs={12} md={8}>
          <Typography variant="subtitle2" gutterBottom>Category Breakdown</Typography>
          {categoryOrder.map(({ key, name, icon }) => {
            const category = categories[key as keyof typeof categories];
            if (!category) return null;
            
            return (
              <Box key={key} sx={{ mb: 2 }}>
                <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 0.5 }}>
                  <Typography variant="body2" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                    <span>{icon}</span> {name}
                    <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>
                      ({category.weight * 100}% weight)
                    </Typography>
                  </Typography>
                  <Typography variant="body2" fontWeight={600}>
                    {category.score}/{category.max_score} ({category.percentage}%)
                  </Typography>
                </Box>
                <LinearProgress 
                  variant="determinate" 
                  value={category.percentage} 
                  sx={{ 
                    height: 8, 
                    borderRadius: 4,
                    bgcolor: alpha(theme.palette.grey[500], 0.2),
                    "& .MuiLinearProgress-bar": {
                      bgcolor: category.percentage >= 70 
                        ? theme.palette.success.main 
                        : category.percentage >= 40 
                          ? theme.palette.warning.main 
                          : theme.palette.error.main,
                    }
                  }}
                />
                {/* Findings preview */}
                {category.findings && category.findings.length > 0 && (
                  <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                    {category.findings.slice(0, 2).map((finding, idx) => (
                      <Chip 
                        key={idx}
                        label={finding.issue}
                        size="small"
                        sx={{ 
                          fontSize: 10, 
                          height: 20,
                          bgcolor: alpha(getRiskColor(finding.severity), 0.1),
                          color: getRiskColor(finding.severity),
                        }}
                      />
                    ))}
                    {category.findings.length > 2 && (
                      <Chip label={`+${category.findings.length - 2}`} size="small" sx={{ fontSize: 10, height: 20 }} />
                    )}
                  </Box>
                )}
              </Box>
            );
          })}
        </Grid>
      </Grid>

      {/* Attack Surface Summary */}
      <Divider sx={{ my: 2 }} />
      <Typography variant="subtitle2" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <span>🎯</span> Attack Surface Summary
      </Typography>
      <Grid container spacing={1}>
        {hardeningScore.attack_surface_summary && (
          <>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.exported_components}</Typography>
                <Typography variant="caption" color="text.secondary">Exported</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.deep_links}</Typography>
                <Typography variant="caption" color="text.secondary">Deep Links</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.dangerous_permissions}</Typography>
                <Typography variant="caption" color="text.secondary">Dangerous Perms</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Paper sx={{ p: 1.5, textAlign: "center", bgcolor: alpha(theme.palette.background.default, 0.5) }}>
                <Typography variant="h6">{hardeningScore.attack_surface_summary.native_libraries}</Typography>
                <Typography variant="caption" color="text.secondary">Native Libs</Typography>
              </Paper>
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                label={hardeningScore.attack_surface_summary.debug_enabled ? "Debug ON" : "Debug OFF"}
                size="small"
                color={hardeningScore.attack_surface_summary.debug_enabled ? "error" : "success"}
                sx={{ width: "100%" }}
              />
            </Grid>
            <Grid item xs={6} sm={4} md={2}>
              <Chip
                label={hardeningScore.attack_surface_summary.cleartext_traffic ? "Cleartext" : "Encrypted"}
                size="small"
                color={hardeningScore.attack_surface_summary.cleartext_traffic ? "warning" : "success"}
                sx={{ width: "100%" }}
              />
            </Grid>
          </>
        )}
      </Grid>

      {/* Top Risks & Quick Wins */}
      <Grid container spacing={2} sx={{ mt: 1 }}>
        {hardeningScore.top_risks && hardeningScore.top_risks.length > 0 && (
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.error.main, 0.05), height: "100%" }}>
              <Typography variant="subtitle2" color="error.main" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <span>⚠️</span> Top Security Risks
              </Typography>
              <List dense>
                {hardeningScore.top_risks.slice(0, 5).map((risk, idx) => (
                  <ListItem key={idx} sx={{ py: 0.25 }}>
                    <ListItemText
                      primary={<Typography variant="body2">{risk}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        )}
        {hardeningScore.quick_wins && hardeningScore.quick_wins.length > 0 && (
          <Grid item xs={12} md={6}>
            <Paper sx={{ p: 2, bgcolor: alpha(theme.palette.success.main, 0.05), height: "100%" }}>
              <Typography variant="subtitle2" color="success.main" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                <span>✨</span> Quick Security Wins
              </Typography>
              <List dense>
                {hardeningScore.quick_wins.slice(0, 5).map((win, idx) => (
                  <ListItem key={idx} sx={{ py: 0.25 }}>
                    <ListItemText
                      primary={<Typography variant="body2">{win}</Typography>}
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          </Grid>
        )}
      </Grid>
    </Paper>
  );
}

// Docker Analysis Results Component
function DockerResults({ result }: { result: DockerAnalysisResult }) {
  const theme = useTheme();

  return (
    <Box>
      {/* Image Info */}
      <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.background.paper, 0.7) }}>
        <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
          <DockerIcon color="info" /> Docker Image Information
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <Typography variant="caption" color="text.secondary">Image Name</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.image_name}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Image ID</Typography>
            <Typography variant="body1" fontFamily="monospace">{result.image_id.slice(0, 12)}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Total Size</Typography>
            <Typography variant="body1">{result.total_size_human}</Typography>
          </Grid>
          <Grid item xs={6} sm={3}>
            <Typography variant="caption" color="text.secondary">Total Layers</Typography>
            <Typography variant="body1">{result.total_layers}</Typography>
          </Grid>
          {result.base_image && (
            <Grid item xs={6} sm={3}>
              <Typography variant="caption" color="text.secondary">Base Image</Typography>
              <Typography variant="body1">{result.base_image}</Typography>
            </Grid>
          )}
        </Grid>
      </Paper>

      {/* Security Issues */}
      {result.security_issues.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <BugIcon color="error" /> Security Issues ({result.security_issues.length})
          </Typography>
          <List dense>
            {result.security_issues.map((issue, idx) => (
              <ListItem key={idx}>
                <ListItemIcon>
                  <Chip
                    label={issue.severity}
                    size="small"
                    sx={{
                      bgcolor: alpha(getSeverityColor(issue.severity), 0.2),
                      color: getSeverityColor(issue.severity),
                      fontWeight: 600,
                    }}
                  />
                </ListItemIcon>
                <ListItemText
                  primary={issue.description}
                  secondary={issue.command ? (
                    <Typography
                      variant="caption"
                      fontFamily="monospace"
                      sx={{ wordBreak: "break-all" }}
                    >
                      {issue.command}
                    </Typography>
                  ) : issue.category}
                />
              </ListItem>
            ))}
          </List>
        </Paper>
      )}

      {/* Secrets in Layers */}
      {result.secrets.length > 0 && (
        <Paper sx={{ p: 3, mb: 3, bgcolor: alpha(theme.palette.error.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <SecretIcon color="error" /> Secrets in Image Layers ({result.secrets.length})
          </Typography>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Layer</TableCell>
                  <TableCell>Type</TableCell>
                  <TableCell>Value</TableCell>
                  <TableCell>Severity</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.secrets.map((secret, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Tooltip title={secret.layer_command}>
                        <Typography variant="body2" fontFamily="monospace">
                          {secret.layer_id.slice(0, 8)}
                        </Typography>
                      </Tooltip>
                    </TableCell>
                    <TableCell>{secret.secret_type}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                        {secret.masked_value}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={secret.severity}
                        size="small"
                        sx={{
                          bgcolor: alpha(getSeverityColor(secret.severity), 0.2),
                          color: getSeverityColor(secret.severity),
                        }}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Image Layers */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <LayersIcon color="primary" /> Image Layers ({result.layers.length})
          </Typography>
        </AccordionSummary>
        <AccordionDetails>
          <TableContainer sx={{ maxHeight: 400 }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell width={100}>Layer</TableCell>
                  <TableCell width={100}>Size</TableCell>
                  <TableCell>Command</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.layers.map((layer, idx) => (
                  <TableRow key={idx}>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {layer.id.slice(0, 8)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {layer.size > 0 ? `${(layer.size / (1024 * 1024)).toFixed(1)} MB` : "0 B"}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        fontFamily="monospace"
                        sx={{
                          wordBreak: "break-all",
                          maxWidth: 600,
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                        }}
                      >
                        {layer.command.length > 200 ? layer.command.slice(0, 200) + "..." : layer.command}
                      </Typography>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </AccordionDetails>
      </Accordion>

      {/* AI Analysis */}
      {result.ai_analysis && (
        <Paper sx={{ p: 3, mt: 3, bgcolor: alpha(theme.palette.info.main, 0.05) }}>
          <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon color="info" /> AI Analysis
          </Typography>
          <Typography
            variant="body2"
            component="pre"
            sx={{
              whiteSpace: "pre-wrap",
              fontFamily: "inherit",
              m: 0,
            }}
          >
            {result.ai_analysis}
          </Typography>
        </Paper>
      )}
    </Box>
  );
}

// ============================================================================
// Hex Viewer Component
// ============================================================================

function HexViewer() {
  const theme = useTheme();
  const [file, setFile] = useState<File | null>(null);
  const [fileId, setFileId] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string>("");
  const [totalSize, setTotalSize] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const [hexData, setHexData] = useState<HexViewResult | null>(null);
  const [currentOffset, setCurrentOffset] = useState(0);
  const [bytesPerPage] = useState(512);
  
  const [searchQuery, setSearchQuery] = useState("");
  const [searchType, setSearchType] = useState<"text" | "hex">("text");
  const [searchResults, setSearchResults] = useState<HexSearchResponse | null>(null);
  const [searching, setSearching] = useState(false);

  const handleFileSelect = async (selectedFile: File) => {
    setFile(selectedFile);
    setFileName(selectedFile.name);
    setError(null);
    setLoading(true);
    setSearchResults(null);
    
    try {
      const result = await reverseEngineeringClient.uploadForHexView(selectedFile);
      setFileId(result.file_id);
      setTotalSize(result.file_size);
      
      // Load first chunk
      const hexResult = await reverseEngineeringClient.getHexView(result.file_id, 0, bytesPerPage);
      setHexData(hexResult);
      setCurrentOffset(0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to upload file");
    } finally {
      setLoading(false);
    }
  };

  const loadHexData = async (offset: number) => {
    if (!fileId) return;
    setLoading(true);
    try {
      const result = await reverseEngineeringClient.getHexView(fileId, offset, bytesPerPage);
      setHexData(result);
      setCurrentOffset(offset);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load hex data");
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!fileId || !searchQuery) return;
    setSearching(true);
    setError(null);
    try {
      const result = await reverseEngineeringClient.searchHex(fileId, searchQuery, searchType, 50);
      setSearchResults(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Search failed");
    } finally {
      setSearching(false);
    }
  };

  const goToOffset = (offset: number) => {
    const alignedOffset = Math.floor(offset / 16) * 16;
    loadHexData(alignedOffset);
    setSearchResults(null);
  };

  const formatOffset = (offset: number) => offset.toString(16).toUpperCase().padStart(8, "0");

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <HexIcon color="primary" /> Interactive Hex Viewer
      </Typography>

      {/* File Upload */}
      {!fileId && (
        <Box
          sx={{
            border: `2px dashed ${theme.palette.divider}`,
            borderRadius: 2,
            p: 4,
            textAlign: "center",
            cursor: "pointer",
            "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.05) },
          }}
          onClick={() => document.getElementById("hex-file-input")?.click()}
        >
          <input
            id="hex-file-input"
            type="file"
            hidden
            onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
          />
          <UploadIcon sx={{ fontSize: 48, color: "text.secondary", mb: 1 }} />
          <Typography>Click to select a file for hex viewing</Typography>
          <Typography variant="caption" color="text.secondary">
            Any binary file up to 500MB
          </Typography>
        </Box>
      )}

      {loading && <LinearProgress sx={{ my: 2 }} />}
      
      {error && (
        <Alert severity="error" sx={{ my: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Hex View Display */}
      {fileId && hexData && (
        <Box>
          {/* File Info & Controls */}
          <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
            <Box>
              <Typography variant="subtitle1">{fileName}</Typography>
              <Typography variant="caption" color="text.secondary">
                {totalSize.toLocaleString()} bytes | Viewing offset 0x{formatOffset(currentOffset)} - 0x{formatOffset(currentOffset + hexData.length)}
              </Typography>
            </Box>
            <Button
              variant="outlined"
              size="small"
              onClick={() => {
                setFileId(null);
                setFile(null);
                setHexData(null);
                setSearchResults(null);
              }}
            >
              Load Different File
            </Button>
          </Box>

          {/* Navigation */}
          <Box sx={{ display: "flex", gap: 1, mb: 2, flexWrap: "wrap", alignItems: "center" }}>
            <IconButton
              onClick={() => goToOffset(0)}
              disabled={currentOffset === 0}
              size="small"
            >
              <FirstPageIcon />
            </IconButton>
            <IconButton
              onClick={() => loadHexData(Math.max(0, currentOffset - bytesPerPage))}
              disabled={currentOffset === 0}
              size="small"
            >
              <PrevIcon />
            </IconButton>
            <TextField
              size="small"
              label="Go to offset (hex)"
              placeholder="e.g., 1000"
              sx={{ width: 150 }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  const input = (e.target as HTMLInputElement).value;
                  const offset = parseInt(input, 16);
                  if (!isNaN(offset)) goToOffset(offset);
                }
              }}
            />
            <IconButton
              onClick={() => loadHexData(currentOffset + bytesPerPage)}
              disabled={currentOffset + bytesPerPage >= totalSize}
              size="small"
            >
              <NextIcon />
            </IconButton>
            <IconButton
              onClick={() => goToOffset(totalSize - bytesPerPage)}
              disabled={currentOffset + bytesPerPage >= totalSize}
              size="small"
            >
              <LastPageIcon />
            </IconButton>
          </Box>

          {/* Search */}
          <Box sx={{ display: "flex", gap: 1, mb: 2, alignItems: "center" }}>
            <TextField
              size="small"
              label="Search"
              placeholder={searchType === "hex" ? "4d 5a 90 00" : "MZ"}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              sx={{ flexGrow: 1 }}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={searchType === "hex"}
                  onChange={(e) => setSearchType(e.target.checked ? "hex" : "text")}
                  size="small"
                />
              }
              label="Hex"
            />
            <Button
              variant="contained"
              onClick={handleSearch}
              disabled={searching || !searchQuery}
              startIcon={searching ? <CircularProgress size={16} /> : <SearchIcon />}
            >
              Search
            </Button>
          </Box>

          {/* Search Results */}
          {searchResults && searchResults.results.length > 0 && (
            <Paper variant="outlined" sx={{ p: 2, mb: 2, maxHeight: 200, overflow: "auto" }}>
              <Typography variant="subtitle2" gutterBottom>
                Found {searchResults.total_matches} matches for "{searchResults.query}"
              </Typography>
              <List dense>
                {searchResults.results.slice(0, 20).map((match, idx) => (
                  <ListItem
                    key={idx}
                    sx={{ cursor: "pointer", "&:hover": { bgcolor: alpha(theme.palette.primary.main, 0.1) } }}
                    onClick={() => goToOffset(match.offset)}
                  >
                    <ListItemText
                      primary={
                        <Typography variant="body2" fontFamily="monospace">
                          Offset: 0x{match.offset_hex}
                        </Typography>
                      }
                      secondary={
                        <Typography variant="caption" fontFamily="monospace" sx={{ wordBreak: "break-all" }}>
                          {match.context_ascii}
                        </Typography>
                      }
                    />
                  </ListItem>
                ))}
              </List>
            </Paper>
          )}

          {/* Hex Display Table */}
          <TableContainer
            component={Paper}
            variant="outlined"
            sx={{
              fontFamily: "monospace",
              fontSize: "13px",
              maxHeight: 500,
              "& .MuiTableCell-root": {
                py: 0.5,
                px: 1,
                fontFamily: "monospace",
                fontSize: "13px",
              },
            }}
          >
            <Table size="small" stickyHeader>
              <TableHead>
                <TableRow>
                  <TableCell sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1), width: 90 }}>Offset</TableCell>
                  <TableCell sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1) }}>
                    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
                  </TableCell>
                  <TableCell sx={{ bgcolor: alpha(theme.palette.primary.main, 0.1), width: 150 }}>ASCII</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {hexData.rows.map((row, idx) => (
                  <TableRow
                    key={idx}
                    sx={{
                      "&:nth-of-type(odd)": { bgcolor: alpha(theme.palette.action.hover, 0.5) },
                    }}
                  >
                    <TableCell sx={{ color: theme.palette.primary.main, fontWeight: 600 }}>
                      {row.offset_hex}
                    </TableCell>
                    <TableCell>{row.hex}</TableCell>
                    <TableCell sx={{ color: theme.palette.text.secondary }}>{row.ascii}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Box>
      )}
    </Paper>
  );
}

// Main Component
export default function ReverseEngineeringHub() {
  const theme = useTheme();
  const [searchParams] = useSearchParams();
  const projectId = searchParams.get('projectId') ? parseInt(searchParams.get('projectId')!) : undefined;
  const projectName = searchParams.get('projectName') ? decodeURIComponent(searchParams.get('projectName')!) : undefined;
  
  const [activeTab, setActiveTab] = useState(0);
  const [status, setStatus] = useState<ReverseEngineeringStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [includeAi, setIncludeAi] = useState(true);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Binary state
  const [binaryFile, setBinaryFile] = useState<File | null>(null);
  const [binaryResult, setBinaryResult] = useState<BinaryAnalysisResult | null>(null);
  const [binaryLoading, setBinaryLoading] = useState(false);

  // APK state
  const [apkFile, setApkFile] = useState<File | null>(null);
  const [apkResult, setApkResult] = useState<ApkAnalysisResult | null>(null);
  const [apkLoading, setApkLoading] = useState(false);

  // JADX Decompilation state (lifted for sharing with AI tools)
  const [jadxResult, setJadxResult] = useState<JadxDecompilationResult | null>(null);

  // AI Reports state (lifted for saving)
  const [aiFunctionalityReport, setAiFunctionalityReport] = useState<string | null>(null);
  const [aiSecurityReport, setAiSecurityReport] = useState<string | null>(null);
  const [aiPrivacyReport, setAiPrivacyReport] = useState<string | null>(null);
  const [aiThreatModel, setAiThreatModel] = useState<Record<string, unknown> | null>(null);
  const [aiVulnScanResult, setAiVulnScanResult] = useState<Record<string, unknown> | null>(null);
  const [aiChatHistory, setAiChatHistory] = useState<Array<Record<string, unknown>> | null>(null);

  // Docker state
  const [dockerImages, setDockerImages] = useState<DockerImageInfo[]>([]);
  const [selectedImage, setSelectedImage] = useState<string>("");
  const [dockerResult, setDockerResult] = useState<DockerAnalysisResult | null>(null);
  const [dockerLoading, setDockerLoading] = useState(false);

  // Saved reports state
  const [savedReports, setSavedReports] = useState<REReportSummary[]>([]);
  const [reportsLoading, setReportsLoading] = useState(false);
  const [savingReport, setSavingReport] = useState(false);

  // Load status on mount
  useEffect(() => {
    loadStatus();
    loadSavedReports();
  }, []);

  const loadStatus = async () => {
    try {
      setLoading(true);
      const s = await reverseEngineeringClient.getStatus();
      setStatus(s);

      // If Docker is available, load images
      if (s.docker_available) {
        const imgs = await reverseEngineeringClient.listDockerImages();
        setDockerImages(imgs.images);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const loadSavedReports = async () => {
    try {
      setReportsLoading(true);
      const reports = await reverseEngineeringClient.listReports({ limit: 50 });
      setSavedReports(reports);
    } catch (e: any) {
      console.error("Failed to load reports:", e);
    } finally {
      setReportsLoading(false);
    }
  };

  const saveBinaryReport = async () => {
    if (!binaryResult || !binaryFile) return;
    try {
      setSavingReport(true);
      const report: SaveREReportRequest = {
        analysis_type: 'binary',
        title: `Binary Analysis: ${binaryResult.filename}`,
        filename: binaryResult.filename,
        project_id: projectId,
        file_type: binaryResult.metadata.file_type,
        architecture: binaryResult.metadata.architecture,
        file_size: binaryResult.metadata.file_size,
        is_packed: binaryResult.metadata.is_packed,
        packer_name: binaryResult.metadata.packer_name || undefined,
        strings_count: binaryResult.strings_count,
        imports_count: binaryResult.imports.length,
        exports_count: binaryResult.exports.length,
        secrets_count: binaryResult.secrets.length,
        suspicious_indicators: binaryResult.suspicious_indicators as any,
        ai_analysis_raw: binaryResult.ai_analysis || undefined,
        full_analysis_data: {
          metadata: binaryResult.metadata,
          strings_sample: binaryResult.strings_sample,
          imports: binaryResult.imports,
          exports: binaryResult.exports,
          secrets: binaryResult.secrets,
        },
      };
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("Binary analysis report saved successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  const saveApkReport = async () => {
    if (!apkResult || !apkFile) return;
    try {
      setSavingReport(true);
      const report: SaveREReportRequest = {
        analysis_type: 'apk',
        title: `APK Analysis: ${apkResult.package_name || apkFile.name}`,
        filename: apkFile.name,
        project_id: projectId,
        package_name: apkResult.package_name,
        version_name: apkResult.version_name,
        min_sdk: apkResult.min_sdk,
        target_sdk: apkResult.target_sdk,
        secrets_count: apkResult.secrets.length,
        permissions: apkResult.permissions as any,
        security_issues: apkResult.security_issues as any,
        ai_analysis_raw: apkResult.ai_analysis || undefined,
        full_analysis_data: {
          package_name: apkResult.package_name,
          version_name: apkResult.version_name,
          version_code: apkResult.version_code,
          permissions: apkResult.permissions,
          components: apkResult.components,
          urls: apkResult.urls,
          secrets: apkResult.secrets,
          native_libraries: apkResult.native_libraries,
          security_issues: apkResult.security_issues,
        },
        // JADX Full Scan Data (Deep Analysis)
        jadx_total_classes: jadxResult?.total_classes,
        jadx_total_files: jadxResult?.total_files,
        jadx_output_directory: jadxResult?.output_directory,
        jadx_classes_sample: jadxResult?.classes?.slice(0, 100).map(c => ({
          class_name: c.class_name,
          package_name: c.package_name,
          is_activity: c.is_activity,
          is_service: c.is_service,
          security_issues_count: c.security_issues_count,
        })) as any,
        jadx_security_issues: jadxResult?.security_issues?.slice(0, 200) as any,
        // AI-Generated Reports (Deep Analysis)
        ai_functionality_report: aiFunctionalityReport || undefined,
        ai_security_report: aiSecurityReport || undefined,
        ai_privacy_report: aiPrivacyReport || undefined,
        ai_threat_model: aiThreatModel as any,
        ai_vuln_scan_result: aiVulnScanResult as any,
        ai_chat_history: aiChatHistory as any,
      };
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("APK analysis report saved successfully (including Full Scan data)!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  const saveDockerReport = async () => {
    if (!dockerResult) return;
    try {
      setSavingReport(true);
      const report: SaveREReportRequest = {
        analysis_type: 'docker',
        title: `Docker Analysis: ${dockerResult.image_name}`,
        filename: dockerResult.image_name,
        project_id: projectId,
        image_name: dockerResult.image_name,
        image_id: dockerResult.image_id,
        total_layers: dockerResult.total_layers,
        base_image: dockerResult.base_image || undefined,
        secrets_count: dockerResult.secrets.length,
        security_issues: dockerResult.security_issues as any,
        ai_analysis_raw: dockerResult.ai_analysis || undefined,
        full_analysis_data: {
          image_name: dockerResult.image_name,
          image_id: dockerResult.image_id,
          total_layers: dockerResult.total_layers,
          total_size: dockerResult.total_size,
          base_image: dockerResult.base_image,
          layers: dockerResult.layers,
          secrets: dockerResult.secrets,
          security_issues: dockerResult.security_issues,
        },
      };
      await reverseEngineeringClient.saveReport(report);
      setSuccessMessage("Docker analysis report saved successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to save report: ${e.message}`);
    } finally {
      setSavingReport(false);
    }
  };

  const deleteReport = async (reportId: number) => {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
      await reverseEngineeringClient.deleteReport(reportId);
      setSuccessMessage("Report deleted successfully!");
      loadSavedReports();
    } catch (e: any) {
      setError(`Failed to delete report: ${e.message}`);
    }
  };

  // Export a saved report to various formats
  const exportSavedReport = async (reportId: number, format: "markdown" | "pdf" | "docx") => {
    try {
      setSuccessMessage(`Exporting report to ${format.toUpperCase()}...`);
      const blob = await reverseEngineeringClient.exportSavedReport(reportId, format);
      
      // Find the report to get its title for the filename
      const report = savedReports.find(r => r.id === reportId);
      const baseName = report?.title || `report_${reportId}`;
      const safeBaseName = baseName.replace(/[^a-zA-Z0-9-_]/g, '_').substring(0, 50);
      
      // Determine file extension
      const ext = format === "markdown" ? "md" : format;
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${safeBaseName}_full_report.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      
      setSuccessMessage(`Report exported to ${format.toUpperCase()} successfully!`);
    } catch (e: any) {
      setError(`Failed to export report: ${e.message}`);
    }
  };

  const analyzeBinary = async () => {
    if (!binaryFile) return;
    try {
      setBinaryLoading(true);
      setError(null);
      const result = await reverseEngineeringClient.analyzeBinary(binaryFile, includeAi);
      setBinaryResult(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setBinaryLoading(false);
    }
  };

  const analyzeApk = async () => {
    if (!apkFile) return;
    try {
      setApkLoading(true);
      setError(null);
      const result = await reverseEngineeringClient.analyzeApk(apkFile, includeAi);
      setApkResult(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setApkLoading(false);
    }
  };

  const analyzeDocker = async () => {
    if (!selectedImage) return;
    try {
      setDockerLoading(true);
      setError(null);
      const result = await reverseEngineeringClient.analyzeDockerImage(selectedImage, includeAi);
      setDockerResult(result);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDockerLoading(false);
    }
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 3 }}>
        <MuiLink
          component={Link}
          to="/"
          underline="hover"
          sx={{ display: "flex", alignItems: "center", gap: 0.5 }}
        >
          <HomeIcon fontSize="small" />
          Home
        </MuiLink>
        <Typography color="text.primary" sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
          <BinaryIcon fontSize="small" />
          Reverse Engineering Hub
        </Typography>
      </Breadcrumbs>

      {/* Header */}
      <Paper
        sx={{
          p: 4,
          mb: 4,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", gap: 2, mb: 2 }}>
          <ShieldIcon sx={{ fontSize: 48, color: theme.palette.primary.main }} />
          <Box>
            <Typography variant="h4" fontWeight="bold">
              Reverse Engineering Hub
              {projectName && (
                <Chip
                  label={`Project: ${projectName}`}
                  color="primary"
                  size="small"
                  sx={{ ml: 2, verticalAlign: "middle" }}
                />
              )}
            </Typography>
            <Typography variant="body1" color="text.secondary">
              Analyze binaries, APKs, and Docker images for secrets and security issues
              {projectId && " • Reports will be saved to this project"}
            </Typography>
          </Box>
        </Box>

        {/* Status */}
        {loading && <LinearProgress sx={{ mt: 2 }} />}
        {status && (
          <Box sx={{ mt: 2, display: "flex", gap: 2, flexWrap: "wrap" }}>
            <Chip
              icon={<BinaryIcon />}
              label="Binary Analysis"
              color={status.binary_analysis ? "success" : "default"}
              variant={status.binary_analysis ? "filled" : "outlined"}
            />
            <Chip
              icon={<ApkIcon />}
              label="APK Analysis"
              color={status.apk_analysis ? "success" : "default"}
              variant={status.apk_analysis ? "filled" : "outlined"}
            />
            <Chip
              icon={<DockerIcon />}
              label="Docker Analysis"
              color={status.docker_analysis ? "success" : "default"}
              variant={status.docker_analysis ? "filled" : "outlined"}
            />
            <FormControlLabel
              control={
                <Switch
                  checked={includeAi}
                  onChange={(e) => setIncludeAi(e.target.checked)}
                  color="primary"
                />
              }
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <AiIcon fontSize="small" /> AI Analysis
                </Box>
              }
            />
          </Box>
        )}
      </Paper>

      {/* Error Alert */}
      {error && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Success Alert */}
      {successMessage && (
        <Alert severity="success" onClose={() => setSuccessMessage(null)} sx={{ mb: 3 }}>
          {successMessage}
        </Alert>
      )}

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={activeTab}
          onChange={(_, v) => setActiveTab(v)}
          variant="fullWidth"
          sx={{
            borderBottom: 1,
            borderColor: "divider",
            "& .MuiTab-root": { py: 2 },
          }}
        >
          <Tab
            icon={<BinaryIcon />}
            label="Binary Analyzer"
            iconPosition="start"
          />
          <Tab
            icon={<ApkIcon />}
            label="APK Analyzer"
            iconPosition="start"
          />
          <Tab
            icon={<DockerIcon />}
            label="Docker Inspector"
            iconPosition="start"
            disabled={!status?.docker_available}
          />
          <Tab
            icon={<HexIcon />}
            label="Hex Viewer"
            iconPosition="start"
          />
          <Tab
            icon={<HistoryIcon />}
            label={`Saved Reports (${savedReports.length})`}
            iconPosition="start"
          />
        </Tabs>
      </Paper>

        {/* Binary Tab */}
        <TabPanel value={activeTab} index={0}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <FileDropZone
                accept=".exe,.dll,.so,.elf,.bin,.o,.dylib"
                onFileSelect={(f) => {
                  setBinaryFile(f);
                  setBinaryResult(null);
                }}
                label="Upload Binary"
                description="EXE, DLL, ELF, SO files up to 500MB"
                icon={<BinaryIcon sx={{ fontSize: 48 }} />}
                disabled={binaryLoading}
              />
              {binaryFile && (
                <Box sx={{ mt: 2 }}>
                  <Alert severity="info">
                    Selected: <strong>{binaryFile.name}</strong> ({(binaryFile.size / 1024).toFixed(1)} KB)
                  </Alert>
                  <Button
                    variant="contained"
                    fullWidth
                    sx={{ mt: 2 }}
                    onClick={analyzeBinary}
                    disabled={binaryLoading}
                    startIcon={binaryLoading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  >
                    {binaryLoading ? "Analyzing..." : "Analyze Binary"}
                  </Button>
                </Box>
              )}
            </Grid>
            <Grid item xs={12} md={8}>
              {binaryLoading && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <CircularProgress />
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Analyzing binary... This may take a moment.
                  </Typography>
                </Box>
              )}
              {binaryResult && !binaryLoading && (
                <>
                  <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
                    <Button
                      variant="contained"
                      color="success"
                      startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                      onClick={saveBinaryReport}
                      disabled={savingReport}
                    >
                      {savingReport ? "Saving..." : "Save Report"}
                    </Button>
                  </Box>
                  <BinaryResults result={binaryResult} />
                  
                  {/* Entropy Visualization */}
                  <Box sx={{ mt: 4 }}>
                    <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                      📊 Entropy Analysis
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                      Analyze entropy distribution to detect packing, encryption, and obfuscation
                    </Typography>
                    <EntropyVisualizer file={binaryFile} />
                  </Box>
                </>
              )}
              {!binaryFile && !binaryResult && (
                <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
                  <BinaryIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="h6" sx={{ mt: 2 }}>
                    Upload a binary file to analyze
                  </Typography>
                  <Typography variant="body2">
                    Extract strings, imports, metadata, and detect secrets
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </TabPanel>

        {/* APK Tab */}
        <TabPanel value={activeTab} index={1}>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <FileDropZone
                accept=".apk,.aab"
                onFileSelect={(f) => {
                  setApkFile(f);
                  setApkResult(null);
                }}
                label="Upload APK"
                description="Android APK or AAB files up to 500MB"
                icon={<ApkIcon sx={{ fontSize: 48 }} />}
                disabled={apkLoading}
              />
              {apkFile && (
                <Box sx={{ mt: 2 }}>
                  <Alert severity="info">
                    Selected: <strong>{apkFile.name}</strong> ({(apkFile.size / (1024 * 1024)).toFixed(1)} MB)
                  </Alert>
                  <Button
                    variant="contained"
                    fullWidth
                    sx={{ mt: 2 }}
                    onClick={analyzeApk}
                    disabled={apkLoading}
                    startIcon={apkLoading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  >
                    {apkLoading ? "Scanning..." : "Quick Security Scan"}
                  </Button>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block", textAlign: "center" }}>
                    Fast metadata extraction • Permissions • Components • Secrets
                  </Typography>
                </Box>
              )}
            </Grid>
            <Grid item xs={12} md={8}>
              {apkLoading && (
                <Box sx={{ textAlign: "center", py: 4 }}>
                  <CircularProgress />
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                    Analyzing APK... Extracting manifest and DEX files.
                  </Typography>
                </Box>
              )}

              {/* Quick Scan Results - Appears FIRST */}
              {apkResult && !apkLoading && (
                <>
                  <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
                    <Button
                      variant="contained"
                      color="success"
                      startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                      onClick={saveApkReport}
                      disabled={savingReport}
                    >
                      {savingReport ? "Saving..." : "Save Report"}
                    </Button>
                  </Box>
                  <ApkResults result={apkResult} jadxResult={jadxResult} apkFile={apkFile} />
                </>
              )}
              
              {/* Deep Code Analysis (JADX) - Only appears AFTER Quick Scan has completed */}
              {apkFile && !apkLoading && apkResult && (
                <Box id="advanced-apk-analysis" sx={{ mt: 4, scrollMarginTop: "80px" }}>
                  <Typography variant="h5" gutterBottom sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CodeIcon color="primary" /> Deep Code Analysis (JADX)
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Full source code decompilation • Search & navigate code • Crypto audit • Component mapping
                  </Typography>
                  <JadxDecompiler 
                    apkFile={apkFile} 
                    onDecompilationComplete={(result) => setJadxResult(result)}
                  />
                  
                  {/* Deep Analysis Reports - Appear after JADX decompilation completes */}
                  {jadxResult && apkResult && (
                    <DeepAnalysisReports 
                      jadxResult={jadxResult} 
                      quickScanResult={apkResult}
                      onFunctionalityReportGenerated={setAiFunctionalityReport}
                      onSecurityReportGenerated={setAiSecurityReport}
                    />
                  )}
                </Box>
              )}
              {!apkFile && !apkResult && (
                <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
                  <ApkIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                  <Typography variant="h6" sx={{ mt: 2 }}>
                    Upload an Android APK to analyze
                  </Typography>
                  <Typography variant="body2" sx={{ mb: 1 }}>
                    <strong>Quick Scan:</strong> Extract permissions, components, secrets, and URLs
                  </Typography>
                  <Typography variant="body2">
                    <strong>Deep Analysis:</strong> Decompile to Java, search code, audit crypto
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </TabPanel>

        {/* Docker Tab */}
        <TabPanel value={activeTab} index={2}>
          {!status?.docker_available ? (
            <Alert severity="warning">
              Docker is not available. Please install Docker to use this feature.
            </Alert>
          ) : (
            <Grid container spacing={3}>
              <Grid item xs={12} md={4}>
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    Select Docker Image
                  </Typography>
                  <Autocomplete
                    options={dockerImages.map((img) => img.name)}
                    value={selectedImage}
                    onChange={(_, v) => {
                      setSelectedImage(v || "");
                      setDockerResult(null);
                    }}
                    freeSolo
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Image Name"
                        placeholder="e.g., nginx:latest"
                        fullWidth
                      />
                    )}
                  />
                  <Button
                    variant="contained"
                    fullWidth
                    sx={{ mt: 2 }}
                    onClick={analyzeDocker}
                    disabled={dockerLoading || !selectedImage}
                    startIcon={dockerLoading ? <CircularProgress size={20} /> : <SecurityIcon />}
                  >
                    {dockerLoading ? "Analyzing..." : "Analyze Image"}
                  </Button>

                  <Divider sx={{ my: 3 }} />

                  <Typography variant="subtitle2" gutterBottom>
                    Local Images ({dockerImages.length})
                  </Typography>
                  <List dense sx={{ maxHeight: 300, overflow: "auto" }}>
                    {dockerImages.map((img, idx) => (
                      <ListItem
                        key={idx}
                        button
                        onClick={() => {
                          setSelectedImage(img.name);
                          setDockerResult(null);
                        }}
                        selected={selectedImage === img.name}
                      >
                        <ListItemIcon>
                          <DockerIcon color={selectedImage === img.name ? "primary" : "inherit"} />
                        </ListItemIcon>
                        <ListItemText
                          primary={img.name}
                          secondary={`${img.size} • ${img.id}`}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Grid>
              <Grid item xs={12} md={8}>
                {dockerLoading && (
                  <Box sx={{ textAlign: "center", py: 4 }}>
                    <CircularProgress />
                    <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                      Analyzing Docker image layers...
                    </Typography>
                  </Box>
                )}
                {dockerResult && !dockerLoading && (
                  <>
                    <Box sx={{ display: "flex", justifyContent: "flex-end", mb: 2 }}>
                      <Button
                        variant="contained"
                        color="success"
                        startIcon={savingReport ? <CircularProgress size={20} /> : <SaveIcon />}
                        onClick={saveDockerReport}
                        disabled={savingReport}
                      >
                        {savingReport ? "Saving..." : "Save Report"}
                      </Button>
                    </Box>
                    <DockerResults result={dockerResult} />
                  </>
                )}
                {!selectedImage && !dockerResult && (
                  <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
                    <DockerIcon sx={{ fontSize: 64, opacity: 0.3 }} />
                    <Typography variant="h6" sx={{ mt: 2 }}>
                      Select a Docker image to analyze
                    </Typography>
                    <Typography variant="body2">
                      Inspect layers for secrets, credentials, and misconfigurations
                    </Typography>
                  </Box>
                )}
              </Grid>
            </Grid>
          )}
        </TabPanel>

        {/* Hex Viewer Tab */}
        <TabPanel value={activeTab} index={3}>
          <HexViewer />
        </TabPanel>

        {/* Saved Reports Tab */}
        <TabPanel value={activeTab} index={4}>
          <Box sx={{ mb: 3, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <Typography variant="h6">
              Saved Analysis Reports
            </Typography>
            <Button
              variant="outlined"
              startIcon={<RefreshIcon />}
              onClick={loadSavedReports}
              disabled={reportsLoading}
            >
              Refresh
            </Button>
          </Box>

          {reportsLoading && (
            <Box sx={{ textAlign: "center", py: 4 }}>
              <CircularProgress />
            </Box>
          )}

          {!reportsLoading && savedReports.length === 0 && (
            <Box sx={{ textAlign: "center", py: 8, color: "text.secondary" }}>
              <HistoryIcon sx={{ fontSize: 64, opacity: 0.3 }} />
              <Typography variant="h6" sx={{ mt: 2 }}>
                No saved reports yet
              </Typography>
              <Typography variant="body2">
                Analyze a binary, APK, or Docker image and save the report
              </Typography>
            </Box>
          )}

          {!reportsLoading && savedReports.length > 0 && (
            <TableContainer component={Paper}>
              <Table>
                <TableHead>
                  <TableRow>
                    <TableCell>Title</TableCell>
                    <TableCell>Type</TableCell>
                    <TableCell>Risk Level</TableCell>
                    <TableCell>Date</TableCell>
                    <TableCell align="right">Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {savedReports.map((report) => (
                    <TableRow key={report.id} hover>
                      <TableCell>
                        <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                          {report.analysis_type === 'binary' && <BinaryIcon fontSize="small" color="primary" />}
                          {report.analysis_type === 'apk' && <ApkIcon fontSize="small" color="success" />}
                          {report.analysis_type === 'docker' && <DockerIcon fontSize="small" color="info" />}
                          <Box>
                            <Typography variant="body2" fontWeight="medium">
                              {report.title}
                            </Typography>
                            {report.filename && (
                              <Typography variant="caption" color="text.secondary">
                                {report.filename}
                              </Typography>
                            )}
                          </Box>
                        </Box>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={report.analysis_type.toUpperCase()}
                          size="small"
                          color={
                            report.analysis_type === 'binary' ? 'primary' :
                            report.analysis_type === 'apk' ? 'success' : 'info'
                          }
                          variant="outlined"
                        />
                      </TableCell>
                      <TableCell>
                        {report.risk_level ? (
                          <Chip
                            label={report.risk_level}
                            size="small"
                            sx={{
                              bgcolor: alpha(getSeverityColor(report.risk_level), 0.2),
                              color: getSeverityColor(report.risk_level),
                              fontWeight: 600,
                            }}
                          />
                        ) : (
                          <Typography variant="body2" color="text.secondary">—</Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2">
                          {new Date(report.created_at).toLocaleDateString()}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {new Date(report.created_at).toLocaleTimeString()}
                        </Typography>
                      </TableCell>
                      <TableCell align="right">
                        <Box sx={{ display: 'flex', gap: 0.5 }}>
                          <Tooltip title="Export to Markdown">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'markdown')}
                            >
                              <ArticleIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export to PDF">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'pdf')}
                            >
                              <PdfIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Export to Word">
                            <IconButton
                              size="small"
                              color="primary"
                              onClick={() => exportSavedReport(report.id, 'docx')}
                            >
                              <WordIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                          <Tooltip title="Delete Report">
                            <IconButton
                              size="small"
                              color="error"
                              onClick={() => deleteReport(report.id)}
                            >
                              <DeleteIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </Box>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </TabPanel>
      </Container>
  );
}
