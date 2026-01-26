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
import { reverseEngineeringClient, type ApkChatMessage, type ApkChatResponse, type UnifiedApkScanResult } from "../api/client";
import ReactMarkdown from "react-markdown";
import { createChatMarkdownComponents, chatMarkdownContainerSx } from "./ChatMarkdownComponents";

interface ApkChatPanelProps {
  // The main unified scan result
  unifiedScanResult: UnifiedApkScanResult | null;
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
  unifiedScanResult,
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

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Initial suggestions based on analysis
  useEffect(() => {
    if (unifiedScanResult && messages.length === 0) {
      const initialSuggestions = generateInitialSuggestions(unifiedScanResult);
      setCurrentSuggestions(initialSuggestions);
    }
  }, [unifiedScanResult, messages.length]);

  // When a finding is selected, offer to ask about it
  useEffect(() => {
    if (selectedFinding) {
      setCurrentSuggestions([
        `Tell me more about this ${selectedFinding.type} issue`,
        "How can I exploit this vulnerability?",
        "What's the recommended fix for this?",
        "Is this a false positive?",
      ]);
    }
  }, [selectedFinding]);

  const generateInitialSuggestions = (result: UnifiedApkScanResult): string[] => {
    const suggestions: string[] = [];
    
    // Based on findings
    if (result.security_issues?.length > 0) {
      suggestions.push("What are the most critical security issues?");
      suggestions.push("How can I exploit the vulnerabilities found?");
    }
    
    if (result.secrets?.length > 0) {
      suggestions.push("Tell me about the hardcoded secrets found");
    }
    
    // NEW: Sensitive data findings
    const sensitiveFindings = (result as any).sensitive_data_findings?.findings || [];
    if (sensitiveFindings.length > 0) {
      suggestions.push("Explain the sensitive data (passwords, emails, PII) found");
    }
    
    // NEW: CVE findings
    const cveFindings = (result as any).cve_scan_results?.findings || [];
    if (cveFindings.length > 0) {
      suggestions.push("What CVEs affect this app's dependencies?");
    }
    
    // NEW: Verified findings
    const verifiedFindings = (result as any).verification_results?.verified_findings || [];
    if (verifiedFindings.length > 0) {
      suggestions.push("Walk me through the AI-verified vulnerabilities");
    }
    
    if (result.dangerous_permissions_count > 0) {
      suggestions.push("Explain the dangerous permissions this app uses");
    }
    
    // General questions
    if (suggestions.length < 4) {
      suggestions.push("Give me an overview of this APK's security posture");
    }
    
    if (suggestions.length < 4) {
      suggestions.push("What attack vectors should I focus on?");
    }
    
    return suggestions.slice(0, 5);
  };

  const buildAnalysisContext = useCallback(() => {
    if (!unifiedScanResult) return {};
    
    const context: Record<string, unknown> = {
      // Basic app info
      package_name: unifiedScanResult.package_name,
      version_name: unifiedScanResult.version_name,
      version_code: unifiedScanResult.version_code,
      min_sdk: unifiedScanResult.min_sdk,
      target_sdk: unifiedScanResult.target_sdk,
      
      // Permissions
      permissions: unifiedScanResult.permissions,
      dangerous_permissions_count: unifiedScanResult.dangerous_permissions_count,
      
      // Security findings
      security_issues: unifiedScanResult.security_issues,
      secrets: unifiedScanResult.secrets,
      
      // Components
      components: unifiedScanResult.components,
      
      // AI Reports
      ai_functionality_report: unifiedScanResult.ai_functionality_report,
      ai_security_report: unifiedScanResult.ai_security_report,
      ai_architecture_diagram: unifiedScanResult.ai_architecture_diagram,
      ai_attack_surface_map: unifiedScanResult.ai_attack_surface_map,
      
      // NEW: Decompiled code analysis
      decompiled_code_findings: unifiedScanResult.decompiled_code_findings,
      decompiled_code_summary: unifiedScanResult.decompiled_code_summary,
      
      // NEW: Sensitive data discovery (PII, passwords, emails, etc.)
      sensitive_data_findings: unifiedScanResult.sensitive_data_findings,
      
      // NEW: CVE/Vulnerability database scan
      cve_scan_results: unifiedScanResult.cve_scan_results,
      
      // NEW: AI vulnerability hunt results (note: vuln_hunt_result singular)
      vuln_hunt_results: unifiedScanResult.vuln_hunt_result,
      
      // NEW: AI verification results (false positive filtering)
      verification_results: unifiedScanResult.verification_results,
      
      // Dynamic analysis & protections
      dynamic_analysis: unifiedScanResult.dynamic_analysis,
    };

    // Add selected finding context if available
    if (selectedFinding) {
      context.selected_finding = {
        ...selectedFinding,
      };
    }

    // Add source code context if viewing code
    if (currentSourceCode && currentSourceClass) {
      context.current_source_code = {
        class_name: currentSourceClass,
        code_snippet: currentSourceCode.substring(0, 2000), // Truncate for context
      };
    }

    return context;
  }, [unifiedScanResult, selectedFinding, currentSourceCode, currentSourceClass]);

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
      // Build conversation history (last 10 messages)
      const conversationHistory: ApkChatMessage[] = messages
        .slice(-10)
        .map(m => ({
          role: m.role,
          content: m.content,
          timestamp: m.timestamp,
        }));

      const response: ApkChatResponse = await reverseEngineeringClient.chatAboutApk({
        message: textToSend,
        conversation_history: conversationHistory,
        analysis_context: buildAnalysisContext(),
        beginner_mode: beginnerMode,
      });

      const assistantMessage: ChatMessageWithMeta = {
        id: `msg-${Date.now()}-response`,
        role: "assistant",
        content: response.response,
        timestamp: new Date().toISOString(),
        learning_tip: response.learning_tip,
        suggested_questions: response.suggested_questions,
        related_findings: response.related_findings,
      };

      setMessages(prev => [...prev, assistantMessage]);

      // Update suggestions
      if (response.suggested_questions?.length > 0) {
        setCurrentSuggestions(response.suggested_questions);
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
    if (unifiedScanResult) {
      setCurrentSuggestions(generateInitialSuggestions(unifiedScanResult));
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
    a.download = `apk_chat_${unifiedScanResult?.package_name || "analysis"}_${new Date().toISOString().split("T")[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
    setMenuAnchor(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getContextSummary = () => {
    if (!unifiedScanResult) return "No analysis loaded";
    
    const parts: string[] = [];
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
    return parts.join(" • ");
  };

  // FAB button when panel is closed
  if (!isOpen) {
    return (
      <Tooltip title="AI Chat Assistant - Ask questions about this APK">
        <Fab
          color="primary"
          onClick={() => setIsOpen(true)}
          disabled={!unifiedScanResult}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            background: unifiedScanResult
              ? `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`
              : undefined,
            "&:hover": {
              background: unifiedScanResult
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
              APK Analysis Chat
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
                    Hi! I'm your APK analysis assistant.
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    I can help you understand security findings, explain vulnerabilities, suggest exploitation strategies, 
                    and provide beginner-friendly explanations. Ask me anything about this APK!
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
              placeholder="Ask about this APK..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading || !unifiedScanResult}
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
              disabled={!message.trim() || isLoading || !unifiedScanResult}
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
          {!unifiedScanResult && (
            <Typography variant="caption" color="error" sx={{ mt: 1, display: "block" }}>
              Run an APK scan first to enable chat
            </Typography>
          )}
        </Box>
      </Collapse>
    </Paper>
  );
}
