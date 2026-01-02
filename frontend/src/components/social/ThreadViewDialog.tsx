import React, { useState, useRef, useEffect, useCallback } from "react";
import {
  Dialog,
  DialogTitle,
  DialogContent,
  Box,
  Typography,
  Avatar,
  IconButton,
  TextField,
  Button,
  Paper,
  Stack,
  Chip,
  CircularProgress,
  Divider,
  alpha,
  useTheme,
} from "@mui/material";
import {
  Close as CloseIcon,
  Send as SendIcon,
  Reply as ReplyIcon,
  Forum as ThreadIcon,
} from "@mui/icons-material";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { socialApi, SocialMessage } from "../../api/client";
import { MarkdownRenderer } from "./MarkdownRenderer";

interface ThreadViewDialogProps {
  open: boolean;
  onClose: () => void;
  conversationId: number;
  parentMessage: SocialMessage;
  currentUserId?: number;
}

export const ThreadViewDialog: React.FC<ThreadViewDialogProps> = ({
  open,
  onClose,
  conversationId,
  parentMessage,
  currentUserId,
}) => {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const [replyContent, setReplyContent] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch thread replies
  const threadQuery = useQuery({
    queryKey: ["thread", conversationId, parentMessage.id],
    queryFn: () => socialApi.getThreadReplies(conversationId, parentMessage.id),
    enabled: open,
    refetchInterval: open ? 3000 : false,
  });

  const replies = threadQuery.data?.replies || [];
  const totalReplies = threadQuery.data?.total_replies || 0;

  // Send reply mutation
  const sendReplyMutation = useMutation({
    mutationFn: async (content: string) => {
      return socialApi.replyToMessage(conversationId, parentMessage.id, content);
    },
    onSuccess: () => {
      setReplyContent("");
      queryClient.invalidateQueries({ queryKey: ["thread", conversationId, parentMessage.id] });
      queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
    },
  });

  // Scroll to bottom on new messages
  useEffect(() => {
    if (open && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [replies.length, open]);

  // Focus input when dialog opens
  useEffect(() => {
    if (open && inputRef.current) {
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  const handleSendReply = useCallback(() => {
    if (replyContent.trim() && !sendReplyMutation.isPending) {
      sendReplyMutation.mutate(replyContent.trim());
    }
  }, [replyContent, sendReplyMutation]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter" && !e.shiftKey) {
        e.preventDefault();
        handleSendReply();
      }
    },
    [handleSendReply]
  );

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    
    if (isToday) {
      return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    }
    return date.toLocaleDateString([], { month: "short", day: "numeric" }) + 
           " " + date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const renderMessage = (message: SocialMessage, isParent: boolean = false) => {
    const isOwn = message.sender_id === currentUserId;

    return (
      <Box
        key={message.id}
        sx={{
          display: "flex",
          flexDirection: "column",
          alignItems: isOwn ? "flex-end" : "flex-start",
          mb: 2,
          ...(isParent && {
            bgcolor: alpha(theme.palette.primary.main, 0.05),
            p: 2,
            borderRadius: 2,
            border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
            mb: 3,
          }),
        }}
      >
        <Box sx={{ display: "flex", alignItems: isOwn ? "flex-end" : "flex-start", width: "100%" }}>
          {!isOwn && (
            <Avatar
              src={message.sender_avatar_url}
              sx={{ width: 32, height: 32, mr: 1, bgcolor: "primary.main" }}
            >
              {message.sender_username?.charAt(0).toUpperCase()}
            </Avatar>
          )}
          
          <Box sx={{ maxWidth: isParent ? "100%" : "80%", flex: isParent ? 1 : "none" }}>
            <Box sx={{ display: "flex", alignItems: "center", gap: 1, mb: 0.5 }}>
              <Typography variant="caption" fontWeight={500}>
                {message.sender_username}
              </Typography>
              {isParent && (
                <Chip
                  icon={<ThreadIcon sx={{ fontSize: 14 }} />}
                  label="Thread"
                  size="small"
                  color="primary"
                  variant="outlined"
                  sx={{ height: 20, fontSize: "0.65rem" }}
                />
              )}
            </Box>
            
            <Paper
              elevation={0}
              sx={{
                px: 2,
                py: 1,
                bgcolor: isOwn ? "primary.main" : "action.hover",
                color: isOwn ? "primary.contrastText" : "text.primary",
                borderRadius: 2,
                borderTopLeftRadius: !isOwn ? 0 : 16,
                borderTopRightRadius: isOwn ? 0 : 16,
              }}
            >
              <MarkdownRenderer content={message.content} currentUserId={currentUserId} />
            </Paper>
            
            <Typography variant="caption" sx={{ opacity: 0.7, mt: 0.5, display: "block" }}>
              {formatTime(message.created_at)}
              {message.is_edited && " (edited)"}
            </Typography>
          </Box>
          
          {isOwn && (
            <Avatar
              src={message.sender_avatar_url}
              sx={{ width: 32, height: 32, ml: 1, bgcolor: "primary.main" }}
            >
              {message.sender_username?.charAt(0).toUpperCase()}
            </Avatar>
          )}
        </Box>
      </Box>
    );
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="sm"
      fullWidth
      PaperProps={{
        sx: {
          height: "80vh",
          maxHeight: 700,
          display: "flex",
          flexDirection: "column",
        },
      }}
    >
      <DialogTitle sx={{ pb: 1 }}>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Stack direction="row" alignItems="center" spacing={1}>
            <ThreadIcon color="primary" />
            <Typography variant="h6">Thread</Typography>
            <Chip
              label={`${totalReplies} ${totalReplies === 1 ? "reply" : "replies"}`}
              size="small"
              color="primary"
              variant="outlined"
            />
          </Stack>
          <IconButton onClick={onClose} size="small">
            <CloseIcon />
          </IconButton>
        </Stack>
      </DialogTitle>

      <Divider />

      <DialogContent sx={{ flex: 1, overflow: "auto", p: 2 }}>
        {/* Parent Message */}
        {renderMessage(parentMessage, true)}

        {/* Replies */}
        {threadQuery.isLoading ? (
          <Box sx={{ display: "flex", justifyContent: "center", p: 3 }}>
            <CircularProgress size={24} />
          </Box>
        ) : replies.length > 0 ? (
          <>
            <Typography variant="caption" color="text.secondary" sx={{ mb: 2, display: "block" }}>
              {totalReplies} {totalReplies === 1 ? "reply" : "replies"}
            </Typography>
            {replies.map((reply) => renderMessage(reply))}
          </>
        ) : (
          <Box sx={{ textAlign: "center", py: 4 }}>
            <ReplyIcon sx={{ fontSize: 48, opacity: 0.3, mb: 1 }} />
            <Typography color="text.secondary">
              No replies yet. Start the conversation!
            </Typography>
          </Box>
        )}
        <div ref={messagesEndRef} />
      </DialogContent>

      <Divider />

      {/* Reply Input */}
      <Box sx={{ p: 2, bgcolor: "background.paper" }}>
        <Stack direction="row" spacing={1} alignItems="flex-end">
          <TextField
            inputRef={inputRef}
            fullWidth
            multiline
            maxRows={4}
            placeholder="Reply in thread..."
            value={replyContent}
            onChange={(e) => setReplyContent(e.target.value)}
            onKeyDown={handleKeyDown}
            size="small"
            disabled={sendReplyMutation.isPending}
            sx={{
              "& .MuiOutlinedInput-root": {
                borderRadius: 3,
              },
            }}
          />
          <Button
            variant="contained"
            onClick={handleSendReply}
            disabled={!replyContent.trim() || sendReplyMutation.isPending}
            sx={{ minWidth: 48, height: 40 }}
          >
            {sendReplyMutation.isPending ? (
              <CircularProgress size={20} color="inherit" />
            ) : (
              <SendIcon />
            )}
          </Button>
        </Stack>
      </Box>
    </Dialog>
  );
};

export default ThreadViewDialog;
