import React, { useState, useRef, useEffect, useCallback } from "react";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "./ChatCodeBlock";
import {
  Box,
  Paper,
  Typography,
  TextField,
  IconButton,
  Fab,
  Chip,
  Avatar,
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
  Security as SecurityIcon,
  OpenInFull as OpenInFullIcon,
  CloseFullscreen as CloseFullscreenIcon,
  BugReport as ExploitIcon,
  Http as HttpIcon,
} from "@mui/icons-material";

interface MitmChatMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  learning_tip?: string;
  suggested_questions?: string[];
}

interface MitmChatPanelProps {
  analysisResult: any | null;
  trafficLog: any[];
  proxyConfig: any | null;
  rules: any[];
}

export default function MitmChatPanel({
  analysisResult,
  trafficLog,
  proxyConfig,
  rules,
}: MitmChatPanelProps) {
  const theme = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<MitmChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [beginnerMode, setBeginnerMode] = useState(true);
  const [showSuggestions, setShowSuggestions] = useState(true);
  const [currentSuggestions, setCurrentSuggestions] = useState<string[]>([]);
  const [menuAnchor, setMenuAnchor] = useState<HTMLElement | null>(null);
  const [contextExpanded, setContextExpanded] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    if (messages.length === 0) {
      const initialSuggestions = generateInitialSuggestions(analysisResult);
      setCurrentSuggestions(initialSuggestions);
    }
  }, [analysisResult, messages.length]);

  const generateInitialSuggestions = (analysis: any): string[] => {
    const suggestions: string[] = [];

    // If no analysis yet, provide getting-started suggestions
    if (!analysis) {
      return [
        "How do I set up traffic interception?",
        "What should I look for in captured traffic?",
        "What are common MITM attack techniques?",
        "How do I identify vulnerable cookies?",
      ];
    }

    const findings = analysis?.findings || [];
    const attackPaths = analysis?.attack_paths || [];
    
    if (findings.length > 0) {
      suggestions.push("What are the most exploitable vulnerabilities?");
      suggestions.push("How would an attacker exploit these findings?");
    }
    
    if (attackPaths.length > 0) {
      suggestions.push("Walk me through the attack chains identified");
    }
    
    if (analysis?.cve_references?.length > 0) {
      suggestions.push("Explain the CVEs found and their exploit status");
    }
    
    if (analysis?.exploit_references?.length > 0) {
      suggestions.push("What known exploits can I use against this target?");
    }
    
    if (trafficLog.length > 0) {
      suggestions.push("What sensitive data is exposed in the traffic?");
    }
    
    if (suggestions.length < 4) {
      suggestions.push("Give me an attacker's perspective on this application");
    }
    
    if (suggestions.length < 5) {
      suggestions.push("What tools should I use to exploit these issues?");
    }
    
    return suggestions.slice(0, 5);
  };

  const buildAnalysisContext = useCallback(() => {
    if (!analysisResult) return {};
    
    return {
      target: proxyConfig ? `${proxyConfig.target_host}:${proxyConfig.target_port}` : "Unknown",
      proxy_config: proxyConfig,
      risk_level: analysisResult.risk_level,
      risk_score: analysisResult.risk_score,
      findings: analysisResult.findings,
      attack_paths: analysisResult.attack_paths,
      cve_references: analysisResult.cve_references,
      exploit_references: analysisResult.exploit_references,
      ai_writeup: analysisResult.ai_writeup,
      detected_technologies: analysisResult.detected_technologies,
      traffic_count: trafficLog.length,
      traffic_sample: trafficLog.slice(0, 20).map(t => ({
        method: t.request?.method,
        path: t.request?.path,
        status: t.response?.status_code,
      })),
      active_rules: rules.length,
    };
  }, [analysisResult, proxyConfig, trafficLog, rules]);

  const handleSendMessage = async (messageText?: string) => {
    const textToSend = messageText || message.trim();
    if (!textToSend || isLoading) return;

    const userMessage: MitmChatMessage = {
      id: `msg-${Date.now()}`,
      role: "user",
      content: textToSend,
      timestamp: new Date().toISOString(),
    };

    setMessages(prev => [...prev, userMessage]);
    setMessage("");
    setIsLoading(true);

    try {
      // Send last 20 messages for better conversation context
      const conversationHistory = messages.slice(-20).map(m => ({
        role: m.role,
        content: m.content,
      }));

      // Helper to make the API call
      const makeRequest = async (accessToken: string | null) => {
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        if (accessToken) {
          headers["Authorization"] = `Bearer ${accessToken}`;
        }
        return fetch("/api/mitm/chat", {
          method: "POST",
          headers,
          body: JSON.stringify({
            message: textToSend,
            conversation_history: conversationHistory,
            analysis_context: buildAnalysisContext(),
            beginner_mode: beginnerMode,
          }),
        });
      };

      // Try to refresh token
      const tryRefreshToken = async (): Promise<string | null> => {
        const refreshToken = localStorage.getItem("vragent_refresh_token");
        if (!refreshToken) return null;
        try {
          const resp = await fetch("/api/auth/refresh", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });
          if (resp.ok) {
            const tokens = await resp.json();
            localStorage.setItem("vragent_access_token", tokens.access_token);
            localStorage.setItem("vragent_refresh_token", tokens.refresh_token);
            return tokens.access_token;
          }
        } catch {
          // ignore
        }
        return null;
      };

      // Get auth token from localStorage
      let token = localStorage.getItem("vragent_access_token");
      let response = await makeRequest(token);

      // If 401, try refreshing the token and retry
      if (response.status === 401) {
        const newToken = await tryRefreshToken();
        if (newToken) {
          response = await makeRequest(newToken);
        }
      }

      if (!response.ok) {
        let detail = "";
        try {
          const errData = await response.json();
          detail = errData?.detail || errData?.message || "";
        } catch {
          // ignore
        }
        const fallback = response.status === 503
          ? "AI features require GEMINI_API_KEY."
          : response.status === 401
          ? "Session expired. Please refresh the page and log in again."
          : `Chat request failed (${response.status}).`;
        throw new Error(detail || fallback);
      }

      const data = await response.json();

      const assistantMessage: MitmChatMessage = {
        id: `msg-${Date.now()}-response`,
        role: "assistant",
        content: data.response,
        timestamp: new Date().toISOString(),
        learning_tip: data.learning_tip,
        suggested_questions: data.suggested_questions,
      };

      setMessages(prev => [...prev, assistantMessage]);

      if (data.suggested_questions?.length > 0) {
        setCurrentSuggestions(data.suggested_questions);
      }
    } catch (error: any) {
      const errorMessage: MitmChatMessage = {
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
    if (analysisResult) {
      setCurrentSuggestions(generateInitialSuggestions(analysisResult));
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
    a.download = `mitm_chat_${proxyConfig?.target_host || "analysis"}_${new Date().toISOString().split("T")[0]}.md`;
    a.click();
    URL.revokeObjectURL(url);
    setMenuAnchor(null);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getContextSummary = () => {
    if (!analysisResult) return "No analysis loaded";
    
    const parts: string[] = [];
    parts.push(`🎯 ${proxyConfig?.target_host || "Unknown"}:${proxyConfig?.target_port || "?"}`);
    
    const findings = analysisResult.findings || [];
    if (findings.length > 0) {
      const critical = findings.filter((f: any) => f.severity === "critical").length;
      const high = findings.filter((f: any) => f.severity === "high").length;
      if (critical > 0) parts.push(`🔴 ${critical} critical`);
      if (high > 0) parts.push(`🟠 ${high} high`);
    }
    
    if (analysisResult.attack_paths?.length > 0) {
      parts.push(`⚔️ ${analysisResult.attack_paths.length} attack chains`);
    }
    
    if (trafficLog.length > 0) {
      parts.push(`📊 ${trafficLog.length} requests`);
    }
    
    return parts.join(" • ");
  };

  // FAB button when panel is closed (always show, even without analysis)
  if (!isOpen) {
    return (
      <Tooltip title="AI Security Analyst - Ask about vulnerabilities and exploits">
        <Fab
          color="primary"
          onClick={() => setIsOpen(true)}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            background: `linear-gradient(135deg, #dc2626 0%, #ea580c 100%)`,
            "&:hover": {
              background: `linear-gradient(135deg, #b91c1c 0%, #c2410c 100%)`,
            },
          }}
        >
          <Badge badgeContent={messages.length > 0 ? messages.length : undefined} color="error">
            <SecurityIcon />
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
        width: isMaximized ? "auto" : { xs: "calc(100% - 32px)", sm: 440 },
        maxWidth: isMaximized ? "none" : 440,
        borderRadius: 3,
        overflow: "hidden",
        zIndex: 1300,
        boxShadow: `0 8px 32px ${alpha("#000", 0.3)}`,
        transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Header */}
      <Box
        sx={{
          p: 2,
          background: `linear-gradient(135deg, #dc2626 0%, #ea580c 100%)`,
          color: "white",
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
            <ExploitIcon />
            <Typography variant="h6" fontWeight={600}>
              Security Analyst
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
            height: isMaximized ? "calc(66vh - 180px)" : 380,
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
                bgcolor: alpha("#dc2626", 0.1),
                border: `1px solid ${alpha("#dc2626", 0.3)}`,
                borderRadius: 2,
              }}
            >
              <Box sx={{ display: "flex", alignItems: "flex-start", gap: 1.5 }}>
                <Avatar sx={{ bgcolor: "#dc2626", width: 32, height: 32 }}>
                  <ExploitIcon fontSize="small" />
                </Avatar>
                <Box>
                  <Typography variant="body2" color="text.primary" fontWeight={500}>
                    I'm your offensive security analyst.
                  </Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                    I can help you understand exploitation techniques, suggest attack tools, 
                    explain CVEs and known exploits, and guide you through attack scenarios. 
                    Ask me anything about the vulnerabilities found!
                  </Typography>
                  {beginnerMode && (
                    <Chip
                      icon={<BeginnerIcon />}
                      label="Beginner mode ON - I'll explain concepts clearly"
                      size="small"
                      sx={{ 
                        mt: 1, 
                        bgcolor: alpha("#dc2626", 0.15),
                        color: "#dc2626",
                        borderColor: alpha("#dc2626", 0.3),
                      }}
                      variant="outlined"
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
                  bgcolor: msg.role === "user" ? theme.palette.primary.main : "#dc2626",
                  width: 32,
                  height: 32,
                }}
              >
                {msg.role === "user" ? <UserIcon fontSize="small" /> : <ExploitIcon fontSize="small" />}
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
                    "& p": { margin: 0, mb: 1 },
                    "& p:last-child": { mb: 0 },
                    "& ul, & ol": { mt: 0.5, mb: 1, pl: 2.5 },
                    "& li": { mb: 0.25 },
                    "& a": { color: theme.palette.primary.main, textDecoration: "underline" },
                    "& blockquote": {
                      borderLeft: `3px solid ${alpha(theme.palette.primary.main, 0.5)}`,
                      pl: 1.5, ml: 0, my: 1, fontStyle: "italic",
                      color: theme.palette.text.secondary
                    },
                    "& hr": { my: 1.5, border: "none", borderTop: `1px solid ${theme.palette.divider}` },
                    "& table": { borderCollapse: "collapse", width: "100%", my: 1 },
                    "& th, & td": {
                      border: `1px solid ${theme.palette.divider}`,
                      px: 1, py: 0.5, textAlign: "left"
                    },
                    "& th": { bgcolor: alpha(theme.palette.primary.main, 0.1) },
                    wordBreak: "break-word",
                  }}
                >
                  <ReactMarkdown
                    components={{
                      code: ({ className, children }) => (
                        <ChatCodeBlock className={className} theme={theme}>
                          {children}
                        </ChatCodeBlock>
                      ),
                      p: ({ children }) => (
                        <Typography variant="body2" component="p" sx={{ mb: 1 }}>
                          {children}
                        </Typography>
                      ),
                      h1: ({ children }) => (
                        <Typography variant="h6" component="h1" fontWeight={600} sx={{ mt: 1.5, mb: 1 }}>
                          {children}
                        </Typography>
                      ),
                      h2: ({ children }) => (
                        <Typography variant="subtitle1" component="h2" fontWeight={600} sx={{ mt: 1.5, mb: 0.75 }}>
                          {children}
                        </Typography>
                      ),
                      h3: ({ children }) => (
                        <Typography variant="subtitle2" component="h3" fontWeight={600} sx={{ mt: 1, mb: 0.5 }}>
                          {children}
                        </Typography>
                      ),
                      h4: ({ children }) => (
                        <Typography variant="body2" component="h4" fontWeight={600} sx={{ mt: 1, mb: 0.5 }}>
                          {children}
                        </Typography>
                      ),
                      ul: ({ children }) => (
                        <Box component="ul" sx={{ pl: 2, my: 0.5, listStyleType: "disc" }}>
                          {children}
                        </Box>
                      ),
                      ol: ({ children }) => (
                        <Box component="ol" sx={{ pl: 2, my: 0.5, listStyleType: "decimal" }}>
                          {children}
                        </Box>
                      ),
                      li: ({ children }) => (
                        <Typography component="li" variant="body2" sx={{ mb: 0.25, display: "list-item" }}>
                          {children}
                        </Typography>
                      ),
                      a: ({ href, children }) => (
                        <a
                          href={href}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ color: theme.palette.primary.main, textDecoration: "underline" }}
                        >
                          {children}
                        </a>
                      ),
                      strong: ({ children }) => (
                        <strong style={{ fontWeight: 600 }}>{children}</strong>
                      ),
                      em: ({ children }) => (
                        <em style={{ fontStyle: "italic" }}>{children}</em>
                      ),
                      blockquote: ({ children }) => (
                        <Box
                          component="blockquote"
                          sx={{
                            borderLeft: `3px solid ${alpha(theme.palette.primary.main, 0.5)}`,
                            pl: 1.5, ml: 0, my: 1,
                            color: theme.palette.text.secondary,
                            fontStyle: "italic",
                          }}
                        >
                          {children}
                        </Box>
                      ),
                      hr: () => (
                        <Divider sx={{ my: 1.5 }} />
                      ),
                    }}
                  >
                    {msg.content}
                  </ReactMarkdown>
                </Box>

                {/* Learning tip */}
                {msg.learning_tip && (
                  <Box
                    sx={{
                      mt: 1.5,
                      p: 1,
                      bgcolor: alpha(theme.palette.warning.main, 0.1),
                      border: `1px solid ${alpha(theme.palette.warning.main, 0.3)}`,
                      borderRadius: 1,
                    }}
                  >
                    <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                      <TipIcon fontSize="small" color="warning" />
                      <Typography variant="caption" fontWeight={600} color="warning.main">
                        Security Tip
                      </Typography>
                    </Box>
                    <Typography variant="caption" color="text.secondary">
                      {msg.learning_tip}
                    </Typography>
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
              <Avatar sx={{ bgcolor: "#dc2626", width: 32, height: 32 }}>
                <ExploitIcon fontSize="small" />
              </Avatar>
              <Paper elevation={1} sx={{ p: 1.5, borderRadius: 2 }}>
                <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                  <CircularProgress size={16} sx={{ color: "#dc2626" }} />
                  <Typography variant="body2" color="text.secondary">
                    Analyzing attack vectors...
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
                <SuggestIcon fontSize="small" sx={{ color: "#dc2626" }} />
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
                    borderColor: alpha("#dc2626", 0.5),
                    "&:hover": {
                      bgcolor: alpha("#dc2626", 0.1),
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
              placeholder="Ask about exploits, attack techniques..."
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading}
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
              disabled={!message.trim() || isLoading}
              sx={{
                bgcolor: "#dc2626",
                color: "white",
                "&:hover": {
                  bgcolor: "#b91c1c",
                },
                "&.Mui-disabled": {
                  bgcolor: alpha("#dc2626", 0.3),
                  color: alpha("#fff", 0.5),
                },
              }}
            >
              <SendIcon />
            </IconButton>
          </Box>
        </Box>
      </Collapse>
    </Paper>
  );
}
