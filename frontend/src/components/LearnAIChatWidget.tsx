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
  useTheme,
} from "@mui/material";
import SmartToyIcon from "@mui/icons-material/SmartToy";
import SendIcon from "@mui/icons-material/Send";
import CloseIcon from "@mui/icons-material/Close";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import OpenInFullIcon from "@mui/icons-material/OpenInFull";
import CloseFullscreenIcon from "@mui/icons-material/CloseFullscreen";
import AutoAwesomeIcon from "@mui/icons-material/AutoAwesome";
import SchoolIcon from "@mui/icons-material/School";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import CheckIcon from "@mui/icons-material/Check";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import { useLocation } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import { ChatCodeBlock } from "./ChatCodeBlock";

interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
}

interface LearnAIChatWidgetProps {
  pageTitle: string;
  pageContext: string;
}

const LearnAIChatWidget: React.FC<LearnAIChatWidgetProps> = ({
  pageTitle,
  pageContext,
}) => {
  const theme = useTheme();
  const location = useLocation();
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

  // Clear messages when page changes
  useEffect(() => {
    setMessages([]);
  }, [location.pathname]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleClearChat = () => {
    setMessages([]);
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
      // Build conversation history for context
      const conversationHistory = messages.map((m) => ({
        role: m.role,
        content: m.content,
      }));

      const response = await fetch("/api/learn/chat", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: userMessage.content,
          page_title: pageTitle,
          page_context: pageContext,
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

  const suggestedQuestions = [
    "Explain this concept simply",
    "What are common mistakes?",
    "Give me a practical example",
    "How does this relate to real attacks?",
  ];

  // Floating button when closed
  if (!isOpen) {
    return (
      <Tooltip title="Ask AI about this page" placement="left">
        <Fab
          color="primary"
          onClick={() => setIsOpen(true)}
          sx={{
            position: "fixed",
            bottom: 24,
            right: 24,
            background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%)`,
            boxShadow: `0 4px 20px ${alpha("#8b5cf6", 0.5)}`,
            "&:hover": {
              background: `linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #9333ea 100%)`,
              boxShadow: `0 6px 30px ${alpha("#8b5cf6", 0.6)}`,
              transform: "scale(1.05)",
            },
            transition: "all 0.3s ease",
            zIndex: 1300,
          }}
        >
          <Badge
            badgeContent={<AutoAwesomeIcon sx={{ fontSize: 12 }} />}
            sx={{
              "& .MuiBadge-badge": {
                bgcolor: "#fbbf24",
                color: "#78350f",
                minWidth: 18,
                height: 18,
                padding: 0,
              },
            }}
          >
            <SmartToyIcon />
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
        width: isMaximized ? "auto" : isMinimized ? 320 : { xs: "calc(100% - 48px)", sm: 420 },
        maxWidth: isMaximized ? "none" : 420,
        borderRadius: 3,
        overflow: "hidden",
        zIndex: 1300,
        border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        boxShadow: `0 8px 32px ${alpha("#000", 0.2)}, 0 0 0 1px ${alpha(theme.palette.primary.main, 0.1)}`,
        transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
      }}
    >
      {/* Header */}
      <Box
        sx={{
          background: `linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #a855f7 100%)`,
          color: "white",
          p: 1.5,
          display: "flex",
          alignItems: "center",
          gap: 1,
          cursor: "pointer",
        }}
        onClick={() => setIsMinimized(!isMinimized)}
      >
        <Avatar
          sx={{
            width: 32,
            height: 32,
            bgcolor: alpha("#fff", 0.2),
          }}
        >
          <SmartToyIcon sx={{ fontSize: 20 }} />
        </Avatar>
        <Box sx={{ flex: 1 }}>
          <Typography variant="subtitle2" fontWeight={700}>
            Learning Assistant
          </Typography>
          <Typography variant="caption" sx={{ opacity: 0.9, fontSize: "0.7rem" }}>
            Ask questions about: {pageTitle}
          </Typography>
        </Box>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsMaximized(!isMaximized);
          }}
          sx={{ color: "white" }}
        >
          {isMaximized ? <CloseFullscreenIcon /> : <OpenInFullIcon />}
        </IconButton>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsMinimized(!isMinimized);
          }}
          sx={{ color: "white" }}
        >
          {isMinimized ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        </IconButton>
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            setIsOpen(false);
          }}
          sx={{ color: "white" }}
        >
          <CloseIcon />
        </IconButton>
      </Box>

      {/* Chat Content */}
      <Collapse in={!isMinimized}>
        <Box sx={{ display: "flex", flexDirection: "column", height: isMaximized ? "calc(66vh - 120px)" : 400 }}>
          {/* Messages Area */}
          <Box
            sx={{
              flex: 1,
              overflow: "auto",
              p: 2,
              bgcolor: alpha(theme.palette.background.default, 0.5),
              display: "flex",
              flexDirection: "column",
              gap: 1.5,
            }}
          >
            {messages.length === 0 ? (
              <Box sx={{ textAlign: "center", py: 3 }}>
                <SchoolIcon sx={{ fontSize: 48, color: alpha(theme.palette.primary.main, 0.3), mb: 1 }} />
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  Ask me anything about <strong>{pageTitle}</strong>
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
                        height: 24,
                        cursor: "pointer",
                        bgcolor: alpha(theme.palette.primary.main, 0.1),
                        "&:hover": {
                          bgcolor: alpha(theme.palette.primary.main, 0.2),
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
                        borderRadius: 2,
                        bgcolor:
                          msg.role === "user"
                            ? alpha(theme.palette.primary.main, 0.15)
                            : theme.palette.background.paper,
                        border: `1px solid ${
                          msg.role === "user"
                            ? alpha(theme.palette.primary.main, 0.3)
                            : alpha(theme.palette.divider, 0.5)
                        }`,
                        position: "relative",
                      }}
                    >
                      {msg.role === "assistant" && (
                        <Box sx={{ display: "flex", alignItems: "center", gap: 0.5, mb: 0.5 }}>
                          <AutoAwesomeIcon sx={{ fontSize: 14, color: "#8b5cf6" }} />
                          <Typography variant="caption" sx={{ color: "#8b5cf6", fontWeight: 600 }}>
                            AI Assistant
                          </Typography>
                        </Box>
                      )}
                      <Box
                        sx={{
                          wordBreak: "break-word",
                          fontSize: "0.85rem",
                          lineHeight: 1.5,
                          "& p": { m: 0 },
                          "& p:not(:last-child)": { mb: 1 },
                          "& ul, & ol": { pl: 2, m: 0 },
                          "& li": { mb: 0.5 },
                        }}
                      >
                        <ReactMarkdown
                          components={{
                            code: ({ className, children }) => (
                              <ChatCodeBlock className={className} theme={theme}>
                                {children}
                              </ChatCodeBlock>
                            ),
                          }}
                        >
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
                            "&:hover": { opacity: 1 },
                          }}
                        >
                          {copiedId === msg.id ? (
                            <CheckIcon sx={{ fontSize: 14, color: "#22c55e" }} />
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
                    <CircularProgress size={16} />
                    <Typography variant="caption" color="text.secondary">
                      Thinking...
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
              <Divider />
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
                    "&:hover": {
                      bgcolor: alpha(theme.palette.error.main, 0.1),
                      color: theme.palette.error.main,
                    },
                  }}
                />
              </Box>
            </>
          )}

          <Divider />

          {/* Input Area */}
          <Box sx={{ p: 1.5, bgcolor: theme.palette.background.paper }}>
            <Box sx={{ display: "flex", gap: 1, alignItems: "flex-end" }}>
              <TextField
                inputRef={inputRef}
                fullWidth
                multiline
                maxRows={3}
                size="small"
                placeholder="Ask a question..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyPress={handleKeyPress}
                disabled={isLoading}
                sx={{
                  "& .MuiOutlinedInput-root": {
                    borderRadius: 2,
                    fontSize: "0.875rem",
                  },
                }}
              />
              <IconButton
                onClick={handleSend}
                disabled={!input.trim() || isLoading}
                sx={{
                  bgcolor: alpha(theme.palette.primary.main, 0.1),
                  color: theme.palette.primary.main,
                  "&:hover": {
                    bgcolor: alpha(theme.palette.primary.main, 0.2),
                  },
                  "&.Mui-disabled": {
                    bgcolor: alpha(theme.palette.action.disabled, 0.1),
                  },
                }}
              >
                <SendIcon />
              </IconButton>
            </Box>
            <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5, display: "block", textAlign: "center", fontSize: "0.65rem" }}>
              AI responses are generated based on the current page content
            </Typography>
          </Box>
        </Box>
      </Collapse>
    </Paper>
  );
};

export default LearnAIChatWidget;
