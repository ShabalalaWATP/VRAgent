import React, { useState, useRef, useEffect } from "react";
import {
  Box,
  Paper,
  Typography,
  TextField,
  IconButton,
  Collapse,
  Fab,
  Badge,
  Avatar,
  CircularProgress,
  Tooltip,
  alpha,
  Divider,
  Chip,
  keyframes,
} from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SendIcon from "@mui/icons-material/Send";
import CloseIcon from "@mui/icons-material/Close";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";
import SecurityIcon from "@mui/icons-material/Security";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import RadarIcon from "@mui/icons-material/Radar";
import BugReportIcon from "@mui/icons-material/BugReport";
import ReactMarkdown from "react-markdown";
import { createChatMarkdownComponents, chatMarkdownContainerSx } from "./ChatMarkdownComponents";
import { DynamicScanResult } from "../api/client";

// Cyber theme colors matching the Dynamic Scanner page
const CYBER_COLORS = {
  primary: '#00ff41',
  primaryDark: '#00cc33',
  primaryLight: '#39ff14',
  secondary: '#00ffaa',
  accent: '#00fff7',
  danger: '#ff0055',
  warning: '#ffcc00',
  info: '#00d4ff',
  dark: '#0a0f0a',
  darkAlt: '#0d1810',
  surface: '#101a10',
  text: '#e0ffe0',
  textMuted: '#7fff7f',
  success: '#00ff88',
};

// Animations
const pulseGlow = keyframes`
  0%, 100% { box-shadow: 0 0 10px ${alpha(CYBER_COLORS.primary, 0.4)}, 0 0 20px ${alpha(CYBER_COLORS.primary, 0.2)}; }
  50% { box-shadow: 0 0 20px ${alpha(CYBER_COLORS.primary, 0.6)}, 0 0 40px ${alpha(CYBER_COLORS.primary, 0.3)}; }
`;

const scanLine = keyframes`
  0% { transform: translateY(-100%); }
  100% { transform: translateY(100%); }
`;

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface DynamicScanAIChatWidgetProps {
  scanResult: DynamicScanResult | null;
  scanId: string | null;
}

const DynamicScanAIChatWidget: React.FC<DynamicScanAIChatWidgetProps> = ({
  scanResult,
  scanId,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isMaximized, setIsMaximized] = useState(false);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Scroll to bottom when messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Focus input when opened
  useEffect(() => {
    if (isOpen && !isMinimized) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [isOpen, isMinimized]);

  // Clear messages when scan changes
  useEffect(() => {
    setMessages([]);
  }, [scanId]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleClearChat = () => {
    setMessages([]);
  };

  // Build comprehensive scan context for the AI
  const buildScanContext = (): string => {
    if (!scanResult) return "No scan data available yet.";

    const parts: string[] = [];
    
    parts.push(`=== DYNAMIC SECURITY SCAN REPORT ===`);
    parts.push(`Target: ${scanResult.target}`);
    parts.push(`Status: ${scanResult.status}`);
    parts.push(`Started: ${scanResult.started_at || 'N/A'}`);
    parts.push(`Duration: ${scanResult.duration_seconds || 'N/A'} seconds`);
    parts.push('');

    // Hosts discovered
    if (scanResult.hosts && scanResult.hosts.length > 0) {
      parts.push(`=== DISCOVERED HOSTS (${scanResult.hosts.length}) ===`);
      scanResult.hosts.forEach((host) => {
        parts.push(`Host: ${host.ip} (${host.hostname || 'no hostname'})`);
        parts.push(`  OS: ${host.os || 'Unknown'}`);
        const openPorts = host.ports?.filter(p => p.state === 'open') || [];
        if (openPorts.length > 0) {
          parts.push(`  Open Ports:`);
          openPorts.slice(0, 20).forEach(p => {
            parts.push(`    - ${p.port}/${p.protocol || 'tcp'}: ${p.service || 'unknown'} ${p.version || ''} ${p.product || ''}`);
          });
          if (openPorts.length > 20) {
            parts.push(`    ... and ${openPorts.length - 20} more ports`);
          }
        }
      });
      parts.push('');
    }

    // Findings
    if (scanResult.findings && scanResult.findings.length > 0) {
      parts.push(`=== VULNERABILITY FINDINGS (${scanResult.findings.length}) ===`);
      
      // Group by severity
      const bySeverity: Record<string, typeof scanResult.findings> = {};
      scanResult.findings.forEach(f => {
        const sev = f.severity?.toLowerCase() || 'unknown';
        if (!bySeverity[sev]) bySeverity[sev] = [];
        bySeverity[sev].push(f);
      });

      ['critical', 'high', 'medium', 'low', 'info'].forEach(sev => {
        if (bySeverity[sev]?.length) {
          parts.push(`\n[${sev.toUpperCase()}] (${bySeverity[sev].length} findings)`);
          bySeverity[sev].slice(0, 10).forEach(f => {
            parts.push(`  • ${f.title}`);
            parts.push(`    Host: ${f.host}:${f.port || 'N/A'}`);
            parts.push(`    Source: ${f.source}`);
            if (f.cve_id) parts.push(`    CVE: ${f.cve_id}`);
            if (f.exploit_available) parts.push(`    ⚠️ EXPLOIT AVAILABLE`);
            if (f.description) parts.push(`    Description: ${f.description.slice(0, 200)}...`);
          });
          if (bySeverity[sev].length > 10) {
            parts.push(`  ... and ${bySeverity[sev].length - 10} more ${sev} findings`);
          }
        }
      });
      parts.push('');
    }

    // Attack narrative
    if (scanResult.attack_narrative) {
      parts.push(`=== AI ATTACK NARRATIVE ===`);
      parts.push(scanResult.attack_narrative);
      parts.push('');
    }

    // Exploit chains
    if (scanResult.exploit_chains && scanResult.exploit_chains.length > 0) {
      parts.push(`=== EXPLOIT CHAINS ===`);
      scanResult.exploit_chains.forEach((chain, i) => {
        parts.push(`Chain ${i + 1}: ${chain.name || 'Unnamed'}`);
        parts.push(`  Description: ${chain.description || 'N/A'}`);
        if (chain.steps?.length) {
          parts.push(`  Steps: ${chain.steps.join(' -> ')}`);
        }
        parts.push(`  Impact: ${chain.impact || 'Unknown'}`);
        parts.push(`  Likelihood: ${chain.likelihood || 'Unknown'}`);
      });
      parts.push('');
    }

    // Recommendations
    if (scanResult.recommendations && scanResult.recommendations.length > 0) {
      parts.push(`=== RECOMMENDATIONS ===`);
      scanResult.recommendations.forEach((rec, i) => {
        parts.push(`${i + 1}. ${rec}`);
      });
      parts.push('');
    }

    // Exploit commands
    if (scanResult.exploit_commands && Object.keys(scanResult.exploit_commands).length > 0) {
      parts.push(`=== EXPLOITATION COMMANDS ===`);
      Object.entries(scanResult.exploit_commands).forEach(([tool, cmds]) => {
        parts.push(`[${tool}]`);
        (cmds as string[]).slice(0, 5).forEach(cmd => {
          parts.push(`  ${cmd}`);
        });
      });
    }

    const context = parts.join('\n');
    const maxChars = 15000;
    if (context.length <= maxChars) {
      return context;
    }
    return `${context.slice(0, maxChars)}\n... (context truncated for chat)`;
  };

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);

    try {
      // Build conversation history
      const conversationHistory = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const scanContext = buildScanContext();

      const response = await fetch("/api/dynamic-scan/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: userMessage.content,
          scan_context: scanContext,
          scan_id: scanId,
          conversation_history: conversationHistory,
        }),
      });

      if (!response.ok) {
        throw new Error("Failed to get response");
      }

      const data = await response.json();

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: data.response || "I apologize, but I couldn't generate a response. Please try again.",
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, assistantMessage]);
    } catch (error) {
      console.error("Chat error:", error);
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "assistant",
        content: "I'm sorry, I encountered an error. Please make sure the backend is running and try again.",
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const suggestedQuestions = scanResult ? [
    "What are the most critical risks?",
    "How would you exploit this target?",
    "What should I patch first?",
    "Explain the attack narrative",
    "Suggest manual testing steps",
  ] : [
    "Start a scan to analyze",
    "What can you help with?",
  ];

  // Floating button when closed
  if (!isOpen) {
    return (
      <Tooltip title="Ask AI about this scan" placement="left">
        <Fab
          onClick={() => setIsOpen(true)}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            background: `linear-gradient(135deg, ${CYBER_COLORS.dark} 0%, ${CYBER_COLORS.darkAlt} 100%)`,
            border: `2px solid ${CYBER_COLORS.primary}`,
            boxShadow: `0 0 20px ${alpha(CYBER_COLORS.primary, 0.5)}, inset 0 0 20px ${alpha(CYBER_COLORS.primary, 0.1)}`,
            animation: `${pulseGlow} 2s ease-in-out infinite`,
            "&:hover": {
              background: `linear-gradient(135deg, ${CYBER_COLORS.darkAlt} 0%, ${CYBER_COLORS.surface} 100%)`,
              boxShadow: `0 0 30px ${alpha(CYBER_COLORS.primary, 0.7)}, inset 0 0 30px ${alpha(CYBER_COLORS.primary, 0.2)}`,
              transform: "scale(1.05)",
            },
            transition: "all 0.3s ease",
            zIndex: 1300,
          }}
        >
          <Badge
            badgeContent={scanResult?.findings?.length || 0}
            color="error"
            max={99}
            sx={{
              "& .MuiBadge-badge": {
                bgcolor: CYBER_COLORS.danger,
                color: "white",
                fontWeight: "bold",
                fontSize: "0.65rem",
              },
            }}
          >
            <RadarIcon sx={{ color: CYBER_COLORS.primary }} />
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
        bottom: 24,
        right: 24,
        left: isMaximized ? { xs: 24, md: 280 } : "auto",
        width: isMaximized ? "auto" : isMinimized ? 360 : { xs: "calc(100% - 48px)", sm: 450 },
        maxWidth: isMaximized ? "none" : 450,
        borderRadius: 2,
        overflow: "hidden",
        zIndex: 1300,
        border: `1px solid ${CYBER_COLORS.primary}`,
        boxShadow: `0 0 30px ${alpha(CYBER_COLORS.primary, 0.3)}, 0 8px 32px ${alpha("#000", 0.4)}`,
        transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
        bgcolor: CYBER_COLORS.dark,
      }}
    >
      {/* Header */}
      <Box
        sx={{
          background: `linear-gradient(135deg, ${CYBER_COLORS.dark} 0%, ${alpha(CYBER_COLORS.primary, 0.15)} 100%)`,
          borderBottom: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
          color: CYBER_COLORS.text,
          p: 1.5,
          display: "flex",
          alignItems: "center",
          gap: 1,
          cursor: "pointer",
          position: "relative",
          overflow: "hidden",
        }}
        onClick={() => setIsMinimized(!isMinimized)}
      >
        {/* Scan line effect */}
        <Box
          sx={{
            position: "absolute",
            left: 0,
            right: 0,
            top: 0,
            height: "100%",
            background: `linear-gradient(180deg, transparent 0%, ${alpha(CYBER_COLORS.primary, 0.1)} 50%, transparent 100%)`,
            animation: `${scanLine} 3s linear infinite`,
            pointerEvents: "none",
          }}
        />
        
        <Avatar
          sx={{
            width: 36,
            height: 36,
            bgcolor: alpha(CYBER_COLORS.primary, 0.2),
            border: `1px solid ${CYBER_COLORS.primary}`,
          }}
        >
          <SecurityIcon sx={{ fontSize: 20, color: CYBER_COLORS.primary }} />
        </Avatar>
        <Box sx={{ flex: 1 }}>
          <Typography 
            variant="subtitle2" 
            sx={{ 
              fontFamily: '"Share Tech Mono", monospace',
              fontWeight: 700,
              color: CYBER_COLORS.primary,
              letterSpacing: '0.05em',
            }}
          >
            SCAN ANALYST AI
          </Typography>
          <Typography 
            variant="caption" 
            sx={{ 
              color: CYBER_COLORS.textMuted, 
              fontSize: "0.7rem",
              fontFamily: '"Share Tech Mono", monospace',
            }}
          >
            {scanResult ? `Analyzing: ${scanResult.target}` : 'No active scan'}
          </Typography>
        </Box>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsMaximized(!isMaximized);
          }}
          sx={{ color: CYBER_COLORS.primary }}
        >
          {isMaximized ? <CloseFullscreenIcon /> : <OpenInFullIcon />}
        </IconButton>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsMinimized(!isMinimized);
          }}
          sx={{ color: CYBER_COLORS.primary }}
        >
          {isMinimized ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(false);
          }}
          sx={{ color: CYBER_COLORS.danger }}
        >
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Chat Content */}
      <Collapse in={!isMinimized}>
        <Box sx={{ display: "flex", flexDirection: "column", height: isMaximized ? "calc(66vh - 120px)" : 420 }}>
          {/* Scan Stats Bar */}
          {scanResult && (
            <Box 
              sx={{ 
                display: 'flex', 
                gap: 2, 
                px: 2, 
                py: 1, 
                bgcolor: alpha(CYBER_COLORS.primary, 0.05),
                borderBottom: `1px solid ${alpha(CYBER_COLORS.primary, 0.1)}`,
              }}
            >
              <Chip 
                icon={<BugReportIcon sx={{ fontSize: 14, color: `${CYBER_COLORS.danger} !important` }} />}
                label={`${scanResult.findings?.filter(f => f.severity?.toLowerCase() === 'critical').length || 0} Crit`}
                size="small"
                sx={{ 
                  bgcolor: alpha(CYBER_COLORS.danger, 0.1), 
                  color: CYBER_COLORS.danger,
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.7rem',
                  height: 22,
                }}
              />
              <Chip 
                label={`${scanResult.findings?.filter(f => f.severity?.toLowerCase() === 'high').length || 0} High`}
                size="small"
                sx={{ 
                  bgcolor: alpha(CYBER_COLORS.warning, 0.1), 
                  color: CYBER_COLORS.warning,
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.7rem',
                  height: 22,
                }}
              />
              <Chip 
                label={`${scanResult.hosts?.length || 0} Hosts`}
                size="small"
                sx={{ 
                  bgcolor: alpha(CYBER_COLORS.info, 0.1), 
                  color: CYBER_COLORS.info,
                  fontFamily: '"Share Tech Mono", monospace',
                  fontSize: '0.7rem',
                  height: 22,
                }}
              />
            </Box>
          )}

          {/* Messages Area */}
          <Box
            sx={{
              flex: 1,
              overflow: "auto",
              p: 2,
              bgcolor: CYBER_COLORS.dark,
              display: "flex",
              flexDirection: "column",
              gap: 1.5,
              // Custom scrollbar
              "&::-webkit-scrollbar": { width: 6 },
              "&::-webkit-scrollbar-track": { bgcolor: alpha(CYBER_COLORS.primary, 0.05) },
              "&::-webkit-scrollbar-thumb": { 
                bgcolor: alpha(CYBER_COLORS.primary, 0.3), 
                borderRadius: 3,
                "&:hover": { bgcolor: alpha(CYBER_COLORS.primary, 0.5) }
              },
            }}
          >
            {messages.length === 0 ? (
              <Box sx={{ textAlign: "center", py: 3 }}>
                <RadarIcon sx={{ fontSize: 48, color: alpha(CYBER_COLORS.primary, 0.3), mb: 1 }} />
                <Typography 
                  variant="body2" 
                  sx={{ 
                    color: CYBER_COLORS.textMuted, 
                    mb: 2,
                    fontFamily: '"Share Tech Mono", monospace',
                  }}
                >
                  {scanResult 
                    ? `Ask me about the scan of ${scanResult.target}`
                    : 'Start a scan to analyze vulnerabilities'
                  }
                </Typography>
                <Box sx={{ display: "flex", flexWrap: "wrap", gap: 0.5, justifyContent: "center" }}>
                  {suggestedQuestions.map((q, i) => (
                    <Chip
                      key={i}
                      label={q}
                      size="small"
                      onClick={() => {
                        setInput(q);
                        inputRef.current?.focus();
                      }}
                      sx={{
                        fontSize: "0.7rem",
                        height: 26,
                        cursor: "pointer",
                        bgcolor: alpha(CYBER_COLORS.primary, 0.1),
                        color: CYBER_COLORS.text,
                        border: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
                        fontFamily: '"Share Tech Mono", monospace',
                        "&:hover": {
                          bgcolor: alpha(CYBER_COLORS.primary, 0.2),
                          borderColor: CYBER_COLORS.primary,
                        },
                      }}
                    />
                  ))}
                </Box>
              </Box>
            ) : (
              <>
                {messages.map((msg) => (
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
                        p: 1.5,
                        borderRadius: 1,
                        bgcolor: msg.role === "user"
                          ? alpha(CYBER_COLORS.primary, 0.15)
                          : alpha(CYBER_COLORS.surface, 0.8),
                        border: `1px solid ${
                          msg.role === "user"
                            ? alpha(CYBER_COLORS.primary, 0.4)
                            : alpha(CYBER_COLORS.primary, 0.1)
                        }`,
                        position: "relative",
                      }}
                    >
                      {msg.role === "assistant" && (
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                          <SecurityIcon sx={{ fontSize: 14, color: CYBER_COLORS.primary }} />
                          <Typography 
                            variant="caption" 
                            sx={{ 
                              color: CYBER_COLORS.primary, 
                              fontWeight: 600,
                              fontFamily: '"Share Tech Mono", monospace',
                            }}
                          >
                            ANALYST
                          </Typography>
                        </Box>
                      )}
                      <Box
                        sx={{
                          ...chatMarkdownContainerSx,
                          fontSize: "0.85rem",
                          lineHeight: 1.5,
                          color: CYBER_COLORS.text,
                          fontFamily: '"Share Tech Mono", monospace',
                          "& strong": { color: CYBER_COLORS.primary },
                          "& a": { color: CYBER_COLORS.secondary },
                        }}
                      >
                        <ReactMarkdown components={createChatMarkdownComponents({ palette: { mode: 'dark', primary: { main: CYBER_COLORS.primary }, text: { secondary: CYBER_COLORS.textMuted }, divider: alpha(CYBER_COLORS.primary, 0.2) } } as any)}>
                          {msg.content}
                        </ReactMarkdown>
                      </Box>
                      {msg.role === "assistant" && (
                        <IconButton
                          size="small"
                          onClick={() => handleCopy(msg.content, msg.id)}
                          sx={{
                            position: "absolute",
                            top: 4,
                            right: 4,
                            opacity: 0.5,
                            color: CYBER_COLORS.textMuted,
                            "&:hover": { opacity: 1, color: CYBER_COLORS.primary },
                          }}
                        >
                          {copiedId === msg.id ? (
                            <CheckIcon sx={{ fontSize: 14, color: CYBER_COLORS.success }} />
                          ) : (
                            <ContentCopyIcon sx={{ fontSize: 14 }} />
                          )}
                        </IconButton>
                      )}
                    </Box>
                  </Box>
                ))}
                {isLoading && (
                  <Box sx={{ display: "flex", alignItems: "center", gap: 1 }}>
                    <CircularProgress size={16} sx={{ color: CYBER_COLORS.primary }} />
                    <Typography 
                      variant="caption" 
                      sx={{ 
                        color: CYBER_COLORS.textMuted,
                        fontFamily: '"Share Tech Mono", monospace',
                      }}
                    >
                      Analyzing...
                    </Typography>
                  </Box>
                )}
                <div ref={messagesEndRef} />
              </>
            )}
          </Box>

          {/* Clear Chat Button */}
          {messages.length > 0 && (
            <>
              <Divider sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.1) }} />
              <Box sx={{ px: 2, py: 0.5, display: "flex", justifyContent: "center" }}>
                <Chip
                  icon={<DeleteOutlineIcon sx={{ fontSize: 14 }} />}
                  label="Clear chat"
                  size="small"
                  onClick={handleClearChat}
                  sx={{
                    fontSize: "0.7rem",
                    height: 22,
                    cursor: "pointer",
                    bgcolor: "transparent",
                    color: CYBER_COLORS.textMuted,
                    fontFamily: '"Share Tech Mono", monospace',
                    "&:hover": {
                      bgcolor: alpha(CYBER_COLORS.danger, 0.1),
                      color: CYBER_COLORS.danger,
                    },
                  }}
                />
              </Box>
            </>
          )}

          <Divider sx={{ borderColor: alpha(CYBER_COLORS.primary, 0.2) }} />

          {/* Input Area */}
          <Box sx={{ p: 1.5, bgcolor: alpha(CYBER_COLORS.surface, 0.5) }}>
            <Box sx={{ display: "flex", gap: 1, alignItems: "flex-end" }}>
              <TextField
                inputRef={inputRef}
                fullWidth
                multiline
                maxRows={3}
                size="small"
                placeholder={scanResult ? "Ask about this scan..." : "Start a scan first..."}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={isLoading || !scanResult}
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 1,
                    fontSize: "0.875rem",
                    fontFamily: '"Share Tech Mono", monospace',
                    bgcolor: alpha(CYBER_COLORS.dark, 0.5),
                    color: CYBER_COLORS.text,
                    "& fieldset": { borderColor: alpha(CYBER_COLORS.primary, 0.3) },
                    "&:hover fieldset": { borderColor: CYBER_COLORS.primary },
                    "&.Mui-focused fieldset": { 
                      borderColor: CYBER_COLORS.primary,
                      boxShadow: `0 0 10px ${alpha(CYBER_COLORS.primary, 0.2)}`,
                    },
                  },
                  "& .MuiInputBase-input::placeholder": {
                    color: CYBER_COLORS.textMuted,
                    opacity: 0.7,
                  },
                }}
              />
              <IconButton
                onClick={handleSend}
                disabled={!input.trim() || isLoading || !scanResult}
                sx={{
                  bgcolor: alpha(CYBER_COLORS.primary, 0.15),
                  color: CYBER_COLORS.primary,
                  border: `1px solid ${alpha(CYBER_COLORS.primary, 0.3)}`,
                  "&:hover": {
                    bgcolor: alpha(CYBER_COLORS.primary, 0.25),
                    boxShadow: `0 0 15px ${alpha(CYBER_COLORS.primary, 0.3)}`,
                  },
                  "&.Mui-disabled": {
                    bgcolor: alpha(CYBER_COLORS.primary, 0.05),
                    color: alpha(CYBER_COLORS.textMuted, 0.3),
                    borderColor: alpha(CYBER_COLORS.primary, 0.1),
                  },
                }}
              >
                <SendIcon />
              </IconButton>
            </Box>
            <Typography 
              variant="caption" 
              sx={{ 
                mt: 0.5, 
                display: "block", 
                textAlign: "center", 
                fontSize: "0.65rem",
                color: alpha(CYBER_COLORS.textMuted, 0.6),
                fontFamily: '"Share Tech Mono", monospace',
              }}
            >
              AI has full context of scan results & findings
            </Typography>
          </Box>
        </Box>
      </Collapse>
    </Paper>
  );
};

export default DynamicScanAIChatWidget;
