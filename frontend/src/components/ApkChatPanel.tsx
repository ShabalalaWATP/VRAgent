import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  Box,
  Paper,
  Typography,
  TextField,
  IconButton,
  Fab,
  Chip,
  Avatar,
  Button,
  CircularProgress,
  Collapse,
  Tooltip,
  Switch,
  FormControlLabel,
  Divider,
  alpha,
  useTheme,
  Badge,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
} from "@mui/material";
import {
  Chat as ChatIcon,
  Send as SendIcon,
  Close as CloseIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  SmartToy as AiIcon,
  Person as UserIcon,
  School as BeginnerIcon,
  AutoAwesome as SuggestIcon,
  ContentCopy as CopyIcon,
  Download as ExportIcon,
  Delete as ClearIcon,
  Lightbulb as TipIcon,
  Psychology as ContextIcon,
  MoreVert as MoreIcon,
  FindInPage as FindingIcon,
  Security as SecurityIcon,
  OpenInFull as OpenInFullIcon,
  CloseFullscreen as CloseFullscreenIcon,
} from "@mui/icons-material";
import {
  reverseEngineeringClient,
  type ApkChatMessage,
  type ApkChatResponse,
  type BinaryAnalysisResult,
  type DockerAnalysisResult,
  type UnifiedApkScanResult,
} from "../api/client";
import ReactMarkdown from "react-markdown";
import { createChatMarkdownComponents, chatMarkdownContainerSx } from "./ChatMarkdownComponents";

type AnalyzerChatMode = "apk" | "binary" | "docker";

interface ApkChatPanelProps {
  mode?: AnalyzerChatMode;
  // Context key to reset chat when switching scan/report
  chatContextKey?: string;
  // Analyzer results
  unifiedScanResult?: UnifiedApkScanResult | null;
  binaryResult?: BinaryAnalysisResult | null;
  dockerResult?: DockerAnalysisResult | null;
  // Optional: Selected finding context (when user clicks "Ask about this")
  selectedFinding?: {
    type: string;
    title: string;
    description: string;
    severity?: string;
    code_snippet?: string;
  } | null;
  // Optional: Currently viewed source code
  currentSourceCode?: string | null;
  currentSourceClass?: string | null;
  // Callbacks
  onNavigateToFinding?: (findingId: string) => void;
}

interface ChatMessageWithMeta extends ApkChatMessage {
  id: string;
  learning_tip?: string;
  suggested_questions?: string[];
  related_findings?: string[];
}

export default function ApkChatPanel({
  mode = "apk",
  chatContextKey,
  unifiedScanResult,
  binaryResult,
  dockerResult,
  selectedFinding,
  currentSourceCode,
  currentSourceClass,
  onNavigateToFinding,
}: ApkChatPanelProps) {
  const theme = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<ChatMessageWithMeta[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [beginnerMode, setBeginnerMode] = useState(true);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [currentSuggestions, setCurrentSuggestions] = useState<string[]>([]);
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const [contextExpanded, setContextExpanded] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const hasAnalysisContext =
    mode === "apk" ? Boolean(unifiedScanResult) :
    mode === "binary" ? Boolean(binaryResult) :
    Boolean(dockerResult);
  const analyzerLabel =
    mode === "apk" ? "APK Analyzer" :
    mode === "binary" ? "Binary Analyzer" :
    "Docker Inspector";
  const resolvedContextKey = chatContextKey || [
    mode,
    mode === "apk"
      ? (unifiedScanResult?.scan_id || unifiedScanResult?.package_name || "none")
      : mode === "binary"
        ? (binaryResult?.filename || "none")
        : (dockerResult?.image_id || dockerResult?.image_name || "none"),
  ].join(":");

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Reset chat on analyzer/report switch
  useEffect(() => {
    setMessages([]);
    setMessage("");
    setCurrentSuggestions([]);
    setContextExpanded(false);
  }, [resolvedContextKey]);

  // When a finding is selected, offer to ask about it
  useEffect(() => {
    if (mode === "apk" && selectedFinding) {
      setCurrentSuggestions([
        `Tell me more about this ${selectedFinding.type} issue`,
        "How can I exploit this vulnerability?",
        "What's the recommended fix for this?",
        "Is this a false positive?",
      ]);
    }
  }, [selectedFinding, mode]);

  const generateInitialSuggestions = useCallback((): string[] => {
    const suggestions: string[] = [];
    if (mode === "apk" && unifiedScanResult) {
      if (unifiedScanResult.security_issues?.length > 0) {
        suggestions.push("What are the most critical security issues?");
        suggestions.push("How can I exploit the vulnerabilities found?");
      }
      if (unifiedScanResult.secrets?.length > 0) {
        suggestions.push("Tell me about the hardcoded secrets found");
      }
      const sensitiveFindings = (unifiedScanResult as any).sensitive_data_findings?.findings || [];
      if (sensitiveFindings.length > 0) {
        suggestions.push("Explain the sensitive data (passwords, emails, PII) found");
      }
      const cveFindings = (unifiedScanResult as any).cve_scan_results?.findings || [];
      if (cveFindings.length > 0) {
        suggestions.push("What CVEs affect this app's dependencies?");
      }
      const verifiedFindings = (unifiedScanResult as any).verification_results?.verified_findings || [];
      if (verifiedFindings.length > 0) {
        suggestions.push("Walk me through the AI-verified vulnerabilities");
      }
      if (unifiedScanResult.dangerous_permissions_count > 0) {
        suggestions.push("Explain the dangerous permissions this app uses");
      }
      if (suggestions.length < 4) {
        suggestions.push("Give me an overview of this APK's security posture");
      }
      if (suggestions.length < 4) {
        suggestions.push("What attack vectors should I focus on?");
      }
    } else if (mode === "binary" && binaryResult) {
      const vulnCount = binaryResult.vuln_hunt_result?.vulnerabilities?.length || 0;
      const patternCount = binaryResult.pattern_scan_result?.findings?.length || 0;
      if (vulnCount + patternCount > 0) {
        suggestions.push("Which binary vulnerabilities are highest risk?");
        suggestions.push("Explain an exploit path from entry point to impact");
      }
      if (binaryResult.secrets?.length > 0) {
        suggestions.push("What secrets were exposed in this binary?");
      }
      if (binaryResult.attack_surface?.entry_points?.length) {
        suggestions.push("Walk me through the attack surface entry points");
      }
      if (suggestions.length < 4) {
        suggestions.push("Summarize what this binary does in beginner-friendly terms");
      }
      if (suggestions.length < 4) {
        suggestions.push("What should I fix first to reduce risk?");
      }
    } else if (mode === "docker" && dockerResult) {
      if (dockerResult.security_issues?.length > 0) {
        suggestions.push("What are the most critical Docker security issues?");
      }
      if ((dockerResult.secrets?.length || 0) + (dockerResult.layer_secrets?.length || 0) > 0) {
        suggestions.push("Explain the secret exposure risk in this container image");
      }
      if ((dockerResult.cve_scan?.total_vulnerabilities || 0) > 0) {
        suggestions.push("Which CVEs should be patched first and why?");
      }
      suggestions.push("Explain the trust boundaries and likely attack paths");
      if (suggestions.length < 4) {
        suggestions.push("Give me a beginner-friendly container hardening plan");
      }
    }
    return suggestions.slice(0, 5);
  }, [mode, unifiedScanResult, binaryResult, dockerResult]);

  // Initial suggestions based on analysis
  useEffect(() => {
    if (hasAnalysisContext && messages.length === 0) {
      setCurrentSuggestions(generateInitialSuggestions());
    }
  }, [hasAnalysisContext, messages.length, generateInitialSuggestions]);

  const buildAnalysisContext = useCallback(() => {
    if (mode === "apk") {
      if (!unifiedScanResult) return {};

      const context: Record<string, unknown> = {
        package_name: unifiedScanResult.package_name,
        version_name: unifiedScanResult.version_name,
        version_code: unifiedScanResult.version_code,
        min_sdk: unifiedScanResult.min_sdk,
        target_sdk: unifiedScanResult.target_sdk,
        permissions: unifiedScanResult.permissions,
        dangerous_permissions_count: unifiedScanResult.dangerous_permissions_count,
        security_issues: unifiedScanResult.security_issues,
        secrets: unifiedScanResult.secrets,
        components: unifiedScanResult.components,
        ai_functionality_report: unifiedScanResult.ai_functionality_report,
        ai_security_report: unifiedScanResult.ai_security_report,
        ai_architecture_diagram: unifiedScanResult.ai_architecture_diagram,
        ai_attack_surface_map: unifiedScanResult.ai_attack_surface_map,
        decompiled_code_findings: unifiedScanResult.decompiled_code_findings,
        decompiled_code_summary: unifiedScanResult.decompiled_code_summary,
        sensitive_data_findings: unifiedScanResult.sensitive_data_findings,
        cve_scan_results: unifiedScanResult.cve_scan_results,
        vuln_hunt_results: unifiedScanResult.vuln_hunt_result,
        verification_results: unifiedScanResult.verification_results,
        dynamic_analysis: unifiedScanResult.dynamic_analysis,
      };

      if (selectedFinding) {
        context.selected_finding = {
          ...selectedFinding,
        };
      }

      if (currentSourceCode && currentSourceClass) {
        context.current_source_code = {
          class_name: currentSourceClass,
          code_snippet: currentSourceCode.substring(0, 2000),
        };
      }

      return context;
    }

    if (mode === "binary") {
      if (!binaryResult) return {};

      const vulnerabilities = [
        ...(binaryResult.vuln_hunt_result?.vulnerabilities || []),
        ...((binaryResult.pattern_scan_result?.findings || []).map((finding, idx) => ({
          id: `pattern-${idx}`,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          function_name: finding.function_name || "",
          description: finding.description,
          technical_details: finding.evidence || "",
          remediation: finding.remediation || "",
          cwe_id: finding.cwe_id,
        }))),
      ];

      return {
        binary_info: {
          filename: binaryResult.filename,
          metadata: binaryResult.metadata,
          strings_count: binaryResult.strings_count,
          imports_count: binaryResult.imports.length,
          exports_count: binaryResult.exports.length,
          secrets_count: binaryResult.secrets.length,
        },
        purpose_analysis: {
          functionality_report: binaryResult.ai_functionality_report || binaryResult.ai_analysis || "",
          security_report: binaryResult.ai_security_report || "",
          legitimacy: binaryResult.is_legitimate_software,
        },
        vulnerabilities,
        attack_surface: binaryResult.attack_surface || {},
        hunt_result: binaryResult.vuln_hunt_result || {
          risk_score: binaryResult.verification_result?.summary?.verified_total || 0,
          executive_summary: binaryResult.ai_security_report || binaryResult.ai_analysis || "",
        },
      };
    }

    if (!dockerResult) return {};

    const dockerVulns = [
      ...(dockerResult.security_issues || []).map((issue, idx) => ({
        id: `docker-issue-${idx}`,
        title: issue.category ? `${issue.category} issue` : "Container security issue",
        severity: issue.severity || "medium",
        category: issue.category || "container-security",
        description: issue.description || "",
        remediation: issue.remediation || "",
      })),
      ...((dockerResult.cve_scan?.vulnerabilities || []).map((cve, idx) => ({
        id: `docker-cve-${idx}`,
        title: cve.id || cve.external_id || cve.title || "CVE finding",
        severity: cve.severity || "medium",
        category: "cve",
        description: cve.description || "",
        remediation: cve.fixed_version ? `Upgrade ${cve.package || cve.package_name} to ${cve.fixed_version}` : "",
      }))),
      ...((dockerResult.layer_secrets || []).map((secret, idx) => ({
        id: `docker-secret-${idx}`,
        title: `Recoverable secret in ${secret.file_path}`,
        severity: secret.severity || "high",
        category: "secrets",
        description: secret.attack_vector || "Potential secret exposure in image layer history.",
        remediation: "Remove secrets from image history and rotate exposed credentials.",
      }))),
    ];

    return {
      binary_info: {
        image_name: dockerResult.image_name,
        image_id: dockerResult.image_id,
        total_layers: dockerResult.total_layers,
        total_size_human: dockerResult.total_size_human,
        base_image: dockerResult.base_image,
      },
      purpose_analysis: {
        summary: dockerResult.ai_analysis || dockerResult.adjudication_summary || "",
      },
      vulnerabilities: dockerVulns,
      attack_surface: {
        layers: (dockerResult.layers || []).map((layer) => layer.command),
        exposed_ports: (dockerResult as any).exposed_ports || [],
        env_vars: (dockerResult as any).env_vars || [],
      },
      hunt_result: {
        risk_score:
          (dockerResult.cve_scan?.critical_count || 0) * 10 +
          (dockerResult.cve_scan?.high_count || 0) * 5 +
          (dockerResult.security_issues?.length || 0) * 3,
        executive_summary: dockerResult.ai_analysis || "",
        recommended_focus_areas: [
          "Patch high/critical CVEs",
          "Remove secrets from layers",
          "Harden runtime privileges and exposed interfaces",
        ],
      },
    };
  }, [mode, unifiedScanResult, binaryResult, dockerResult, selectedFinding, currentSourceCode, currentSourceClass]);

  const handleSendMessage = async (messageText?: string) => {
    const textToSend = messageText || message.trim();
    if (!textToSend || isLoading) return;

    const userMessage: ChatMessageWithMeta = {
      id: `msg-${Date.now()}`,
      role: "user",
      content: textToSend,
      timestamp: new Date().toISOString(),
    };

    setMessages(prev => [...prev, userMessage]);
    setMessage("");
    setIsLoading(true);

    try {
      const conversationHistory: ApkChatMessage[] = messages
        .slice(-10)
        .map(m => ({
          role: m.role,
          content: m.content,
          timestamp: m.timestamp,
        }));
      const beginnerPrefix =
        beginnerMode && mode !== "apk"
          ? "Please explain in beginner-friendly language where possible.\n\n"
          : "";
      let responseText = "";
      let responseLearningTip: string | undefined;
      let responseSuggestions: string[] = [];
      let responseFindings: string[] = [];

      if (mode === "apk") {
        const response: ApkChatResponse = await reverseEngineeringClient.chatAboutApk({
          message: textToSend,
          conversation_history: conversationHistory,
          analysis_context: buildAnalysisContext(),
          beginner_mode: beginnerMode,
        });
        responseText = response.response;
        responseLearningTip = response.learning_tip;
        responseSuggestions = response.suggested_questions || [];
        responseFindings = response.related_findings || [];
      } else {
        const response = await reverseEngineeringClient.chatAboutAnalysis({
          message: `${beginnerPrefix}${textToSend}`,
          conversation_history: conversationHistory.map((msg) => ({
            role: msg.role,
            content: msg.content,
          })),
          analysis_context: buildAnalysisContext() as any,
        });
        if (response.error) {
          throw new Error(response.error);
        }
        responseText = response.response;
        responseSuggestions = generateInitialSuggestions();
      }

      const assistantMessage: ChatMessageWithMeta = {
        id: `msg-${Date.now()}-response`,
        role: "assistant",
        content: responseText,
        timestamp: new Date().toISOString(),
        learning_tip: responseLearningTip,
        suggested_questions: responseSuggestions,
        related_findings: responseFindings,
      };

      setMessages(prev => [...prev, assistantMessage]);

      // Update suggestions
      if (responseSuggestions.length > 0) {
        setCurrentSuggestions(responseSuggestions);
      }
    } catch (error: any) {
      const errorMessage: ChatMessageWithMeta = {
        id: `msg-${Date.now()}-error`,
        role: "assistant",
        content: `Sorry, I encountered an error: ${error.message}. Please try again.`,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleSuggestionClick = (suggestion: string) => {
    handleSendMessage(suggestion);
  };

  const handleClearChat = () => {
    setMessages([]);
    if (hasAnalysisContext) {
      setCurrentSuggestions(generateInitialSuggestions());
    }
    setMenuAnchor(null);
  };

  const handleExportChat = () => {
    const chatContent = messages
      .map(m => `[${m.role.toUpperCase()}] ${m.timestamp}\n${m.content}`)
      .join("\n\n---\n\n");
    
    const blob = new Blob([chatContent], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const chatPrefix = mode === "apk" ? "apk" : mode === "binary" ? "binary" : "docker";
    const targetName =
      mode === "apk"
        ? (unifiedScanResult?.package_name || "analysis")
        : mode === "binary"
          ? (binaryResult?.filename || "analysis")
          : (dockerResult?.image_name || "analysis");
    a.download = `${chatPrefix}_chat_${targetName}_${new Date().toISOString().split("T")[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
    setMenuAnchor(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getContextSummary = () => {
    if (!hasAnalysisContext) return `No ${analyzerLabel} analysis loaded`;

    const parts: string[] = [];
    if (mode === "apk" && unifiedScanResult) {
      parts.push(`📦 ${unifiedScanResult.package_name || "Unknown Package"}`);
      if (unifiedScanResult.security_issues?.length) {
        parts.push(`🔴 ${unifiedScanResult.security_issues.length} security issues`);
      }
      if (unifiedScanResult.secrets?.length) {
        parts.push(`🔑 ${unifiedScanResult.secrets.length} secrets`);
      }
      if (selectedFinding) {
        parts.push(`👁️ Viewing: ${selectedFinding.title}`);
      }
      if (currentSourceClass) {
        parts.push(`📄 Code: ${currentSourceClass}`);
      }
    } else if (mode === "binary" && binaryResult) {
      parts.push(`🧠 ${binaryResult.filename || "Unknown Binary"}`);
      parts.push(`📥 ${binaryResult.imports?.length || 0} imports`);
      if (binaryResult.vuln_hunt_result?.vulnerabilities?.length) {
        parts.push(`🔴 ${binaryResult.vuln_hunt_result.vulnerabilities.length} vulnerabilities`);
      }
      if (binaryResult.secrets?.length) {
        parts.push(`🔑 ${binaryResult.secrets.length} secrets`);
      }
    } else if (dockerResult) {
      parts.push(`🐳 ${dockerResult.image_name || "Unknown Image"}`);
      parts.push(`🧱 ${dockerResult.total_layers || 0} layers`);
      if (dockerResult.security_issues?.length) {
        parts.push(`🔴 ${dockerResult.security_issues.length} security issues`);
      }
      const cveTotal = dockerResult.cve_scan?.total_vulnerabilities || 0;
      if (cveTotal > 0) {
        parts.push(`🛡️ ${cveTotal} CVEs`);
      }
    }
    return parts.join(" • ");
  };

  // FAB button when panel is closed
  if (!isOpen) {
    return (
      <Tooltip title={`AI Chat Assistant - Ask questions about this ${analyzerLabel} result`}>
        <Fab
          color="primary"
          onClick={() => setIsOpen(true)}
          disabled={!hasAnalysisContext}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            background: hasAnalysisContext
              ? `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`
              : undefined,
            "&:hover": {
              background: hasAnalysisContext
                ? `linear-gradient(135deg, ${theme.palette.primary.dark} 0%, ${theme.palette.secondary.dark} 100%)`
                : undefined,
            },
          }}
        >
          <Badge badgeContent={messages.length > 0 ? messages.length : undefined} color="error">
            <ChatIcon />
          </Badge>
        </Fab>
      </Tooltip>
    );
  }

  return (
    <Paper
      elevation={8}
      sx={{
        position: "fixed",
        bottom: 16,
        right: 16,
        left: isMaximized ? { xs: 16, md: 280 } : "auto",
        width: isMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 420 },
        maxWidth: isMaximized ? "none" : 420,
        borderRadius: 3,
        overflow: "hidden",
        zIndex: 1300,
        boxShadow: `0 8px 32px ${alpha("#000", 0.2)}`,
        transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 2,
          background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
          color: "white",
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <AiIcon />
            <Typography variant="h6" fontWeight={600}>
              {analyzerLabel} Chat
            </Typography>
          </Box>
          <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
            <IconButton
              size="small"
              sx={{ color: "white" }}
              onClick={(e) => setMenuAnchor(e.currentTarget)}
            >
              <MoreIcon />
            </IconButton>
            <IconButton
              size="small"
              sx={{ color: "white" }}
              onClick={() => setIsMaximized(!isMaximized)}
            >
              {isMaximized ? <CloseFullscreenIcon /> : <OpenInFullIcon />}
            </IconButton>
            <IconButton
              size="small"
              sx={{ color: "white" }}
              onClick={() => setIsMinimized(!isMinimized)}
            >
              {isMinimized ? <ExpandIcon /> : <CollapseIcon />}
            </IconButton>
            <IconButton size="small" sx={{ color: "white" }} onClick={() => setIsOpen(false)}>
              <CloseIcon />
            </IconButton>
          </Box>
        </Box>

        {/* Context indicator */}
        <Collapse in={!isMinimized}>
          <Box
            sx={{
              mt: 1,
              p: 1,
              bgcolor: alpha("#000", 0.2),
              borderRadius: 1,
              cursor: "pointer",
            }}
            onClick={() => setContextExpanded(!contextExpanded)}
          >
            <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
              <ContextIcon fontSize="small" />
              <Typography variant="caption" sx={{ flex: 1 }}>
                Context: {getContextSummary().substring(0, 50)}...
              </Typography>
              {contextExpanded ? <CollapseIcon fontSize="small" /> : <ExpandIcon fontSize="small" />}
            </Box>
            <Collapse in={contextExpanded}>
              <Typography variant="caption" sx={{ mt: 1, display: "block", opacity: 0.9 }}>
                {getContextSummary()}
              </Typography>
            </Collapse>
          </Box>
        </Collapse>

        {/* Beginner mode toggle */}
        <Collapse in={!isMinimized}>
          <Box sx={{ mt: 1, display: "flex", alignItems: "center", gap: 1 }}>
            <FormControlLabel
              control={
                <Switch
                  size="small"
                  checked={beginnerMode}
                  onChange={(e) => setBeginnerMode(e.target.checked)}
                  sx={{
                    "& .MuiSwitch-thumb": { bgcolor: "white" },
                    "& .MuiSwitch-track": { bgcolor: alpha("#fff", 0.3) },
                  }}
                />
              }
              label={
                <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                  <BeginnerIcon fontSize="small" />
                  <Typography variant="caption">Beginner Mode</Typography>
                </Box>
              }
              sx={{ m: 0 }}
            />
          </Box>
        </Collapse>
      </Box>

      {/* Menu */}
      <Menu anchorEl={menuAnchor} open={Boolean(menuAnchor)} onClose={() => setMenuAnchor(null)}>
        <MenuItem onClick={handleExportChat} disabled={messages.length === 0}>
          <ListItemIcon>
            <ExportIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Export Chat</ListItemText>
        </MenuItem>
        <MenuItem onClick={handleClearChat} disabled={messages.length === 0}>
          <ListItemIcon>
            <ClearIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText>Clear Chat</ListItemText>
        </MenuItem>
      </Menu>

      <Collapse in={!isMinimized} sx={{ display: "flex", flexDirection: "column", minHeight: 0 }}>
        {/* Messages */}
        <Box
          sx={{
            height: isMaximized ? "calc(66vh - 180px)" : 350,
            overflowY: "auto",
            p: 2,
            display: "flex",
            flexDirection: "column",
            gap: 2,
            bgcolor: alpha(theme.palette.background.default, 0.5),
            transition: "height 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
          }}
        >
          {/* Welcome message */}
          {messages.length === 0 && (
            <Paper
              elevation={0}
              sx={{
                p: 2,
                bgcolor: alpha(theme.palette.info.main, 0.1),
                border: `1px solid ${alpha(theme.palette.info.main, 0.3)}`,
                borderRadius: 2,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Avatar sx={{ bgcolor: theme.palette.info.main, width: 32, height: 32 }}>
                  <AiIcon fontSize="small" />
                </Avatar>
                <Box>
                  <Typography variant="body2" color="text.primary" fontWeight={500}>
                    {`Hi! I'm your ${analyzerLabel} assistant.`}
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    I can help you understand security findings, explain vulnerabilities, suggest exploitation strategies, 
                    and provide beginner-friendly explanations. Ask me anything about this analysis.
                  </Typography>
                  {beginnerMode && (
                    <Chip
                      icon={<BeginnerIcon />}
                      label="Beginner mode is ON - I'll explain concepts simply"
                      size="small"
                      color="info"
                      variant="outlined"
                      sx={{ mt: 1 }}
                    />
                  )}
                </Box>
              </Box>
            </Paper>
          )}

          {/* Chat messages */}
          {messages.map((msg) => (
            <Box
              key={msg.id}
              sx={{
                display: "flex",
                flexDirection: msg.role === "user" ? "row-reverse" : "row",
                alignItems: "flex-start",
                gap: 1,
              }}
            >
              <Avatar
                sx={{
                  bgcolor: msg.role === "user" ? theme.palette.primary.main : theme.palette.secondary.main,
                  width: 32,
                  height: 32,
                }}
              >
                {msg.role === "user" ? <UserIcon fontSize="small" /> : <AiIcon fontSize="small" />}
              </Avatar>
              <Paper
                elevation={1}
                sx={{
                  p: 1.5,
                  maxWidth: "80%",
                  bgcolor: msg.role === "user" 
                    ? alpha(theme.palette.primary.main, 0.1) 
                    : theme.palette.background.paper,
                  borderRadius: 2,
                  borderTopLeftRadius: msg.role === "user" ? 16 : 4,
                  borderTopRightRadius: msg.role === "user" ? 4 : 16,
                }}
              >
                <Box
                  sx={{
                    ...chatMarkdownContainerSx,
                    fontSize: "0.875rem",
                    lineHeight: 1.6,
                  }}
                >
                  <ReactMarkdown components={createChatMarkdownComponents(theme)}>
                    {msg.content}
                  </ReactMarkdown>
                </Box>

                {/* Learning tip */}
                {msg.learning_tip && (
                  <Box
                    sx={{
                      mt: 1.5,
                      p: 1,
                      bgcolor: alpha(theme.palette.success.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.success.main, 0.3)}`,
                      borderRadius: 1,
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                      <TipIcon fontSize="small" color="success" />
                      <Typography variant="caption" fontWeight={600} color="success.main">
                        Learning Tip
                      </Typography>
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {msg.learning_tip}
                    </Typography>
                  </Box>
                )}

                {/* Related findings */}
                {msg.related_findings && msg.related_findings.length > 0 && (
                  <Box sx={{ mt: 1.5 }}>
                    <Typography variant="caption" fontWeight={600} color="text.secondary">
                      Related Findings:
                    </Typography>
                    <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, mt: 0.5 }}>
                      {msg.related_findings.map((finding, idx) => (
                        <Chip
                          key={idx}
                          label={finding}
                          size="small"
                          icon={<FindingIcon />}
                          onClick={() => onNavigateToFinding?.(finding)}
                          sx={{ cursor: "pointer" }}
                        />
                      ))}
                    </Box>
                  </Box>
                )}

                {/* Copy button */}
                <Box sx={{ display: "flex", justifyContent: "flex-end", mt: 0.5 }}>
                  <Tooltip title="Copy">
                    <IconButton size="small" onClick={() => copyToClipboard(msg.content)}>
                      <CopyIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </Box>
              </Paper>
            </Box>
          ))}

          {/* Loading indicator */}
          {isLoading && (
            <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
              <Avatar sx={{ bgcolor: theme.palette.secondary.main, width: 32, height: 32 }}>
                <AiIcon fontSize="small" />
              </Avatar>
              <Paper elevation={1} sx={{ p: 1.5, borderRadius: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CircularProgress size={16} />
                  <Typography variant="body2" color="text.secondary">
                    Analyzing...
                  </Typography>
                </Box>
              </Paper>
            </Box>
          )}

          <div ref={messagesEndRef} />
        </Box>

        {/* Suggestions */}
        <Collapse in={showSuggestions && currentSuggestions.length > 0 && !isLoading}>
          <Box sx={{ p: 1, bgcolor: alpha(theme.palette.background.paper, 0.8), borderTop: `1px solid ${theme.palette.divider}` }}>
            <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between", mb: 1 }}>
              <Box sx={{ display: "flex", alignItems: "center", gap: 0.5 }}>
                <SuggestIcon fontSize="small" color="primary" />
                <Typography variant="caption" fontWeight={600} color="text.secondary">
                  Suggested Questions
                </Typography>
              </Box>
              <IconButton size="small" onClick={() => setShowSuggestions(false)}>
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
            <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5 }}>
              {currentSuggestions.map((suggestion, idx) => (
                <Chip
                  key={idx}
                  label={suggestion}
                  size="small"
                  variant="outlined"
                  onClick={() => handleSuggestionClick(suggestion)}
                  sx={{
                    cursor: "pointer",
                    "&:hover": {
                      bgcolor: alpha(theme.palette.primary.main, 0.1),
                    },
                  }}
                />
              ))}
            </Box>
          </Box>
        </Collapse>

        {/* Input */}
        <Divider />
        <Box sx={{ p: 2, bgcolor: theme.palette.background.paper }}>
          <Box sx={{ display: "flex", gap: 1 }}>
            <TextField
              fullWidth
              multiline
              maxRows={4}
              placeholder={`Ask about this ${analyzerLabel} result...`}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading || !hasAnalysisContext}
              inputRef={inputRef}
              size="small"
              sx={{
                "& .MuiOutlinedInput-root": {
                  borderRadius: 3,
                },
              }}
            />
            <IconButton
              color="primary"
              onClick={() => handleSendMessage()}
              disabled={!message.trim() || isLoading || !hasAnalysisContext}
              sx={{
                bgcolor: theme.palette.primary.main,
                color: "white",
                "&:hover": {
                  bgcolor: theme.palette.primary.dark,
                },
                "&.Mui-disabled": {
                  bgcolor: alpha(theme.palette.primary.main, 0.3),
                  color: alpha("#fff", 0.5),
                },
              }}
            >
              <SendIcon />
            </IconButton>
          </Box>
          {!hasAnalysisContext && (
            <Typography variant="caption" color="error" sx={{ mt: 1, display: "block" }}>
              {`Run a ${analyzerLabel} scan first to enable chat`}
            </Typography>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
}
