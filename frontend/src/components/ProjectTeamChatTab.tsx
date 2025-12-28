import { useState, useEffect, useRef, useCallback } from "react";
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
  Divider,
  IconButton,
  InputAdornment,
  LinearProgress,
  List,
  ListItem,
  ListItemText,
  ListItemButton,
  ListItemAvatar,
  Paper,
  Popover,
  Skeleton,
  Stack,
  TextField,
  Tooltip,
  Typography,
  alpha,
  useTheme,
  Avatar,
  AvatarGroup,
  Badge,
} from "@mui/material";
import {
  Send as SendIcon,
  Sync as SyncIcon,
  Chat as ChatIcon,
  People as PeopleIcon,
  AttachFile as AttachIcon,
  EmojiEmotions as EmojiIcon,
  Reply as ReplyIcon,
  Close as CloseIcon,
  InsertDriveFile as FileIcon,
  Image as ImageIcon,
  PushPin as PinIcon,
  PushPinOutlined as PinOutlinedIcon,
  Forward as ForwardIcon,
  DoneAll as ReadIcon,
  Done as SentIcon,
  Search as SearchIcon,
  Poll as PollIcon,
  Bookmark as BookmarkIcon,
  BookmarkBorder as BookmarkOutlineIcon,
  History as HistoryIcon,
  // File type icons
  PictureAsPdf as PdfIcon,
  Description as DocIcon,
  TableChart as SpreadsheetIcon,
  Slideshow as PresentationIcon,
  Code as CodeIcon,
  Folder as ArchiveIcon,
  Android as AndroidIcon,
  Apple as AppleIcon,
  Memory as BinaryIcon,
  Security as SecurityIcon,
  Storage as DataIcon,
  TextSnippet as TextIcon,
} from "@mui/icons-material";
import { 
  api, 
  socialApi, 
  SocialMessage, 
  ConversationDetail, 
  AttachmentData,
  PinnedMessageInfo,
  ReadReceiptInfo,
  ConversationParticipant,
  PollResponse,
  MessageType,
} from "../api/client";
import { useAuth } from "../contexts/AuthContext";
import { useChatWebSocket } from "../hooks/useChatWebSocket";
import { MarkdownRenderer } from "./social/MarkdownRenderer";
import { EmojiPicker } from "./social/EmojiPicker";
import { PollCreator } from "./social/PollCreator";
import { PollDisplay } from "./social/PollDisplay";
import { MessageSearchDialog } from "./social/MessageSearchDialog";
import { BookmarksDialog } from "./social/BookmarksDialog";
import { EditHistoryDialog } from "./social/EditHistoryDialog";
import { ImageGallery } from "./social/ImageGallery";

// Common emoji reactions
const COMMON_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🔥', '👏', '🎉'];

// File type detection and icons
const getFileTypeInfo = (filename: string, mimeType?: string): { icon: React.ReactNode; color: string; label: string } => {
  const ext = filename.toLowerCase().split('.').pop() || '';
  
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'tif'].includes(ext)) {
    return { icon: <ImageIcon />, color: '#4CAF50', label: 'Image' };
  }
  if (ext === 'pdf') {
    return { icon: <PdfIcon />, color: '#F44336', label: 'PDF' };
  }
  if (['doc', 'docx', 'odt', 'rtf'].includes(ext)) {
    return { icon: <DocIcon />, color: '#2196F3', label: 'Document' };
  }
  if (['xls', 'xlsx', 'ods', 'csv'].includes(ext)) {
    return { icon: <SpreadsheetIcon />, color: '#4CAF50', label: 'Spreadsheet' };
  }
  if (['ppt', 'pptx', 'odp'].includes(ext)) {
    return { icon: <PresentationIcon />, color: '#FF9800', label: 'Presentation' };
  }
  if (['py', 'js', 'ts', 'jsx', 'tsx', 'java', 'c', 'cpp', 'h', 'cs', 'go', 'rs', 'rb', 'php', 'swift', 'kt', 'scala', 'html', 'css', 'scss', 'vue', 'svelte', 'sql', 'sh', 'bash', 'ps1', 'yaml', 'yml', 'json', 'xml', 'toml', 'ini', 'cfg', 'dockerfile', 'tf', 'proto', 'graphql'].includes(ext)) {
    return { icon: <CodeIcon />, color: '#9C27B0', label: 'Code' };
  }
  if (['zip', 'tar', 'gz', '7z', 'rar', 'tgz', 'bz2', 'xz'].includes(ext)) {
    return { icon: <ArchiveIcon />, color: '#795548', label: 'Archive' };
  }
  if (['apk', 'aab', 'dex', 'smali'].includes(ext)) {
    return { icon: <AndroidIcon />, color: '#3DDC84', label: 'Android' };
  }
  if (['ipa', 'xib', 'storyboard', 'plist'].includes(ext)) {
    return { icon: <AppleIcon />, color: '#007AFF', label: 'iOS' };
  }
  if (['exe', 'dll', 'so', 'dylib', 'elf', 'bin', 'msi', 'deb', 'rpm', 'dmg', 'class', 'jar', 'wasm'].includes(ext)) {
    return { icon: <BinaryIcon />, color: '#607D8B', label: 'Binary' };
  }
  if (['pcap', 'pcapng', 'mem', 'dmp', 'yar', 'yara', 'rules', 'evtx', 'evt'].includes(ext)) {
    return { icon: <SecurityIcon />, color: '#FF5722', label: 'Security' };
  }
  if (['db', 'sqlite', 'sqlite3', 'sql'].includes(ext)) {
    return { icon: <DataIcon />, color: '#00BCD4', label: 'Database' };
  }
  if (['txt', 'md', 'log'].includes(ext)) {
    return { icon: <TextIcon />, color: '#9E9E9E', label: 'Text' };
  }
  return { icon: <FileIcon />, color: '#757575', label: 'File' };
};

const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
};

interface ProjectTeamChatTabProps {
  projectId: number;
  projectName: string;
}

export default function ProjectTeamChatTab({ projectId, projectName }: ProjectTeamChatTabProps) {
  const theme = useTheme();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [newMessage, setNewMessage] = useState("");
  const [replyingTo, setReplyingTo] = useState<SocialMessage | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [isTyping, setIsTyping] = useState(false);
  const [error, setError] = useState("");

  // Feature state
  const [pinnedMessages, setPinnedMessages] = useState<PinnedMessageInfo[]>([]);
  const [showPinnedPanel, setShowPinnedPanel] = useState(false);
  const [readReceipts, setReadReceipts] = useState<ReadReceiptInfo[]>([]);
  const [showMessageSearch, setShowMessageSearch] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [showPollCreator, setShowPollCreator] = useState(false);
  const [conversationPolls, setConversationPolls] = useState<PollResponse[]>([]);
  const [emojiPickerAnchor, setEmojiPickerAnchor] = useState<HTMLElement | null>(null);
  const [showBookmarksDialog, setShowBookmarksDialog] = useState(false);
  const [showEditHistoryDialog, setShowEditHistoryDialog] = useState(false);
  const [editHistoryMessageId, setEditHistoryMessageId] = useState<number | null>(null);
  const [editHistoryContent, setEditHistoryContent] = useState('');
  const [imageGalleryOpen, setImageGalleryOpen] = useState(false);
  const [imageGalleryIndex, setImageGalleryIndex] = useState(0);
  const [mentionSuggestions, setMentionSuggestions] = useState<ConversationParticipant[]>([]);
  const [showMentionSuggestions, setShowMentionSuggestions] = useState(false);
  const [cursorPosition, setCursorPosition] = useState(0);

  // Get or create the team chat
  const teamChatQuery = useQuery({
    queryKey: ["project-team-chat", projectId],
    queryFn: () => api.getProjectTeamChat(projectId),
    enabled: !!projectId,
  });

  const conversationId = teamChatQuery.data?.conversation_id;

  // Get conversation details (messages, participants)
  const conversationQuery = useQuery({
    queryKey: ["conversation", conversationId],
    queryFn: () => conversationId ? socialApi.getConversation(conversationId) : null,
    enabled: !!conversationId,
    refetchInterval: 3000,
  });

  const conversation = conversationQuery.data;
  const messages = conversation?.messages || [];
  const participants = conversation?.participants || [];

  // WebSocket connection
  const {
    status: wsStatus,
    sendTypingIndicator,
    sendViewingConversation,
    sendReadReceipt,
    getTypingUsersForConversation,
  } = useChatWebSocket({
    onNewMessage: (message, convId) => {
      if (conversationId === convId && !message.is_own_message) {
        queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
        sendReadReceipt(convId, message.id);
        socialApi.markConversationRead(convId).catch(() => {});
      }
    },
    onReadReceipt: (convId, userId, lastReadMessageId) => {
      if (conversationId === convId) {
        setReadReceipts(prev => {
          const updated = prev.filter(r => r.user_id !== userId);
          const participant = conversation?.participants.find(p => p.user_id === userId);
          if (participant) {
            updated.push({
              user_id: userId,
              username: participant.username,
              avatar_url: participant.avatar_url,
              last_read_message_id: lastReadMessageId,
              read_at: new Date().toISOString(),
            });
          }
          return updated;
        });
      }
    },
    onMessageEdited: (messageId, convId, content, updatedAt) => {
      if (conversationId === convId) {
        queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
      }
    },
    onMessageDeleted: (messageId, convId) => {
      if (conversationId === convId) {
        queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
      }
    },
    onReactionAdded: () => {
      queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
    },
    onReactionRemoved: () => {
      queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
    },
    onConnectionChange: (_status) => {
      // Connection status handled by useChatWebSocket
    },
  });

  // Send message mutation
  const sendMessageMutation = useMutation({
    mutationFn: async ({ content, replyToId, messageType, attachmentData }: { 
      content: string; 
      replyToId?: number;
      messageType?: MessageType;
      attachmentData?: AttachmentData;
    }) => {
      if (!conversationId) throw new Error("No conversation");
      if (replyToId) {
        return socialApi.replyToMessage(conversationId, replyToId, content);
      }
      return socialApi.sendMessage(conversationId, content, messageType, attachmentData);
    },
    onSuccess: () => {
      setNewMessage("");
      setReplyingTo(null);
      queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
    },
    onError: (err: Error) => {
      setError(err.message);
    },
  });

  // Sync participants mutation
  const syncMutation = useMutation({
    mutationFn: () => api.syncTeamChatParticipants(projectId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
    },
  });

  // Load pinned messages
  const loadPinnedMessages = useCallback(async (convId: number) => {
    try {
      const result = await socialApi.getPinnedMessages(convId);
      setPinnedMessages(result.pinned_messages);
    } catch (err) {
      console.error('Failed to load pinned messages:', err);
    }
  }, []);

  // Load read receipts
  const loadReadReceipts = useCallback(async (convId: number) => {
    try {
      const result = await socialApi.getConversationReadReceipts(convId);
      setReadReceipts(result.receipts);
    } catch (err) {
      console.error('Failed to load read receipts:', err);
    }
  }, []);

  // Load conversation polls
  const loadConversationPolls = useCallback(async (convId: number) => {
    try {
      const result = await socialApi.getConversationPolls(convId);
      setConversationPolls(result);
    } catch (err) {
      console.error('Failed to load polls:', err);
    }
  }, []);

  // Load features when conversation is available
  useEffect(() => {
    if (conversationId) {
      loadPinnedMessages(conversationId);
      loadReadReceipts(conversationId);
      loadConversationPolls(conversationId);
      sendViewingConversation(conversationId);
    }
  }, [conversationId, loadPinnedMessages, loadReadReceipts, loadConversationPolls, sendViewingConversation]);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSendMessage = useCallback(() => {
    if (!newMessage.trim() || !conversationId) return;
    setIsTyping(false);
    sendTypingIndicator(conversationId, false);
    sendMessageMutation.mutate({ 
      content: newMessage.trim(),
      replyToId: replyingTo?.id,
    });
  }, [newMessage, conversationId, replyingTo, sendMessageMutation, sendTypingIndicator]);

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Handle typing indicator and mentions
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    const position = e.target.selectionStart || 0;
    setNewMessage(value);
    setCursorPosition(position);
    
    // Check for mentions
    handleMentionInput(value, position);
    
    if (!isTyping && conversationId) {
      setIsTyping(true);
      sendTypingIndicator(conversationId, true);
    }
    
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    
    typingTimeoutRef.current = setTimeout(() => {
      setIsTyping(false);
      if (conversationId) {
        sendTypingIndicator(conversationId, false);
      }
    }, 2000);
  };

  // Mention handling
  const handleMentionInput = (value: string, position: number) => {
    const textBeforeCursor = value.slice(0, position);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
    
    if (mentionMatch && conversation) {
      const query = mentionMatch[1].toLowerCase();
      const suggestions = conversation.participants.filter(p =>
        p.user_id !== user?.id && 
        (p.username.toLowerCase().includes(query) || 
         p.first_name?.toLowerCase().includes(query))
      );
      setMentionSuggestions(suggestions);
      setShowMentionSuggestions(suggestions.length > 0);
    } else {
      setShowMentionSuggestions(false);
    }
  };

  const insertMention = (participant: ConversationParticipant) => {
    const textBeforeCursor = newMessage.slice(0, cursorPosition);
    const textAfterCursor = newMessage.slice(cursorPosition);
    const mentionStart = textBeforeCursor.lastIndexOf('@');
    const newText = textBeforeCursor.slice(0, mentionStart) + `@${participant.username} ` + textAfterCursor;
    setNewMessage(newText);
    setShowMentionSuggestions(false);
    inputRef.current?.focus();
  };

  // File upload handler
  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !conversationId) return;
    
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    const MAX_SIZE = 1024 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      setError(`File too large. Maximum size is 1GB. Your file is ${formatFileSize(file.size)}`);
      return;
    }

    const fileInfo = getFileTypeInfo(file.name, file.type);
    setUploadProgress(0);
    
    try {
      const uploadResult = await socialApi.uploadFile(file);
      setUploadProgress(100);
      
      const attachmentData: AttachmentData = {
        file_name: uploadResult.filename,
        file_type: uploadResult.mime_type,
        file_size: uploadResult.file_size,
        file_url: uploadResult.file_url,
        thumbnail_url: uploadResult.thumbnail_url,
      };
      
      let messageContent = `Shared a file: ${uploadResult.filename}`;
      if (fileInfo.label === 'Code') {
        messageContent = `Shared code: ${uploadResult.filename}`;
      } else if (fileInfo.label === 'Android' || fileInfo.label === 'iOS') {
        messageContent = `Shared mobile app: ${uploadResult.filename}`;
      } else if (fileInfo.label === 'Archive') {
        messageContent = `Shared archive: ${uploadResult.filename}`;
      } else if (fileInfo.label === 'Image') {
        messageContent = `Shared image: ${uploadResult.filename}`;
      } else if (fileInfo.label === 'Security') {
        messageContent = `Shared security file: ${uploadResult.filename}`;
      }
      
      sendMessageMutation.mutate({
        content: messageContent,
        messageType: 'file',
        attachmentData,
      });
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to upload file';
      setError(errorMsg);
    } finally {
      setUploadProgress(null);
    }
  };

  // Reaction handler
  const handleReaction = async (messageId: number, emoji: string, hasReacted: boolean) => {
    try {
      if (hasReacted) {
        await socialApi.removeReaction(messageId, emoji);
      } else {
        await socialApi.addReaction(messageId, emoji);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update reaction');
    }
  };

  // Pin message handler
  const handlePinMessage = async (messageId: number) => {
    if (!conversationId) return;
    try {
      const isPinned = pinnedMessages.some(p => p.message_id === messageId);
      if (isPinned) {
        await socialApi.unpinMessage(conversationId, messageId);
        setPinnedMessages(prev => prev.filter(p => p.message_id !== messageId));
      } else {
        const pinned = await socialApi.pinMessage(conversationId, messageId);
        setPinnedMessages(prev => [...prev, pinned]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to pin/unpin message');
    }
  };

  // Bookmark handler
  const handleBookmarkMessage = async (messageId: number) => {
    try {
      const isBookmarked = await socialApi.isMessageBookmarked(messageId);
      if (isBookmarked.is_bookmarked) {
        await socialApi.removeBookmark(messageId);
      } else {
        await socialApi.addBookmark(messageId);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update bookmark');
    }
  };

  // View edit history
  const handleViewEditHistory = (message: SocialMessage) => {
    setEditHistoryMessageId(message.id);
    setEditHistoryContent(message.content);
    setShowEditHistoryDialog(true);
  };

  // Get conversation images for gallery
  const getConversationImages = useCallback(() => {
    if (!conversation) return [];
    return conversation.messages
      .filter(m => m.message_type === 'file' && m.attachment_data?.file_type?.startsWith('image/'))
      .map(m => ({
        id: m.id,
        url: m.attachment_data!.file_url!,
        filename: m.attachment_data!.file_name || 'image',
        thumbnailUrl: m.attachment_data!.thumbnail_url,
        senderUsername: m.sender_username,
        createdAt: m.created_at,
      }));
  }, [conversation]);

  const handleImageClick = (messageId: number) => {
    const imageMessages = conversation?.messages
      .filter(m => m.message_type === 'file' && m.attachment_data?.file_type?.startsWith('image/')) || [];
    const index = imageMessages.findIndex(m => m.id === messageId);
    if (index >= 0) {
      setImageGalleryIndex(index);
      setImageGalleryOpen(true);
    }
  };

  // Poll created handler
  const handlePollCreated = async () => {
    if (!conversationId) return;
    loadConversationPolls(conversationId);
    queryClient.invalidateQueries({ queryKey: ["conversation", conversationId] });
  };

  // Navigate to bookmarked message
  const handleNavigateToBookmark = async (convId: number, messageId: number) => {
    // Already in this conversation - just scroll
    // TODO: scroll to specific message
  };

  // Get read receipts for a message
  const getReadByForMessage = (messageId: number) => {
    return readReceipts.filter(r => r.last_read_message_id >= messageId && r.user_id !== user?.id);
  };

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

  const getInitials = (name?: string) => {
    if (!name) return "?";
    return name.split(" ").map(n => n[0]).join("").toUpperCase().slice(0, 2);
  };

  // Loading state
  if (teamChatQuery.isLoading) {
    return (
      <Box sx={{ p: 3 }}>
        <Skeleton variant="rectangular" height={400} sx={{ borderRadius: 2 }} />
      </Box>
    );
  }

  // Error state
  if (teamChatQuery.isError) {
    return (
      <Alert severity="error" sx={{ m: 2 }}>
        {(teamChatQuery.error as Error).message}
      </Alert>
    );
  }

  return (
    <Box sx={{ height: "calc(100vh - 400px)", minHeight: 500, display: "flex", flexDirection: "column" }}>
      {/* Header */}
      <Card
        sx={{
          mb: 2,
          background: `linear-gradient(135deg, ${alpha(theme.palette.primary.main, 0.1)} 0%, ${alpha(theme.palette.secondary.main, 0.1)} 100%)`,
          border: `1px solid ${alpha(theme.palette.primary.main, 0.2)}`,
        }}
      >
        <CardContent sx={{ py: 2 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Stack direction="row" alignItems="center" spacing={2}>
              <Box
                sx={{
                  width: 48,
                  height: 48,
                  borderRadius: 2,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  background: `linear-gradient(135deg, ${theme.palette.primary.main} 0%, ${theme.palette.secondary.main} 100%)`,
                  color: "#fff",
                }}
              >
                <ChatIcon />
              </Box>
              <Box>
                <Typography variant="h6" fontWeight={700}>
                  {teamChatQuery.data?.name || `${projectName} Team Chat`}
                </Typography>
                <Stack direction="row" alignItems="center" spacing={1}>
                  <Chip
                    icon={<PeopleIcon sx={{ fontSize: 16 }} />}
                    label={`${participants.length} members`}
                    size="small"
                    sx={{ height: 24 }}
                  />
                  {wsStatus !== 'connected' && (
                    <Chip
                      label={wsStatus === 'connecting' ? 'Connecting...' : 'Offline'}
                      size="small"
                      color={wsStatus === 'connecting' ? 'warning' : 'error'}
                      sx={{ height: 24 }}
                    />
                  )}
                </Stack>
              </Box>
            </Stack>
            
            <Stack direction="row" alignItems="center" spacing={0.5}>
              {/* Participants */}
              <AvatarGroup max={4} sx={{ mr: 1 }}>
                {participants.slice(0, 4).map((p) => (
                  <Tooltip key={p.user_id} title={p.username || "User"}>
                    <Avatar sx={{ width: 32, height: 32, fontSize: "0.8rem" }}>
                      {getInitials(p.username)}
                    </Avatar>
                  </Tooltip>
                ))}
              </AvatarGroup>
              
              {/* Pinned Messages */}
              {pinnedMessages.length > 0 && (
                <Tooltip title={`${pinnedMessages.length} pinned`}>
                  <IconButton onClick={() => setShowPinnedPanel(!showPinnedPanel)} size="small">
                    <Badge badgeContent={pinnedMessages.length} color="primary">
                      <PinIcon />
                    </Badge>
                  </IconButton>
                </Tooltip>
              )}
              
              {/* Search Messages */}
              <Tooltip title="Search Messages">
                <IconButton onClick={() => setShowMessageSearch(true)} size="small">
                  <SearchIcon />
                </IconButton>
              </Tooltip>
              
              {/* Create Poll */}
              <Tooltip title="Create Poll">
                <IconButton onClick={() => setShowPollCreator(true)} size="small">
                  <PollIcon />
                </IconButton>
              </Tooltip>
              
              {/* Bookmarks */}
              <Tooltip title="View Bookmarks">
                <IconButton onClick={() => setShowBookmarksDialog(true)} size="small">
                  <BookmarkIcon />
                </IconButton>
              </Tooltip>
              
              {/* Sync Participants */}
              <Tooltip title="Sync participants with project collaborators">
                <IconButton 
                  onClick={() => syncMutation.mutate()}
                  disabled={syncMutation.isPending}
                  size="small"
                >
                  <SyncIcon sx={{ animation: syncMutation.isPending ? "spin 1s linear infinite" : "none" }} />
                </IconButton>
              </Tooltip>
            </Stack>
          </Stack>
        </CardContent>
      </Card>

      {/* Pinned Messages Panel */}
      <Collapse in={showPinnedPanel}>
        <Paper sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }} elevation={0}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <PinIcon color="primary" fontSize="small" />
              <Typography variant="subtitle2">Pinned Messages</Typography>
            </Box>
            <IconButton size="small" onClick={() => setShowPinnedPanel(false)}>
              <CloseIcon fontSize="small" />
            </IconButton>
          </Box>
          <List dense sx={{ maxHeight: 200, overflowY: 'auto' }}>
            {pinnedMessages.map((pinned) => (
              <ListItem key={pinned.id} sx={{ px: 1, py: 0.5 }}>
                <ListItemText
                  primary={
                    <Typography variant="body2" noWrap>
                      {pinned.message_content}
                    </Typography>
                  }
                  secondary={
                    <Typography variant="caption" color="text.secondary">
                      {pinned.message_sender} • Pinned by {pinned.pinned_by_username}
                    </Typography>
                  }
                />
                <IconButton 
                  size="small" 
                  onClick={() => handlePinMessage(pinned.message_id)}
                  sx={{ ml: 1 }}
                >
                  <CloseIcon fontSize="small" />
                </IconButton>
              </ListItem>
            ))}
          </List>
        </Paper>
      </Collapse>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError("")}>
          {error}
        </Alert>
      )}

      {/* Messages Area */}
      <Paper
        sx={{
          flex: 1,
          overflow: "auto",
          p: 2,
          background: alpha(theme.palette.background.paper, 0.5),
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 2,
        }}
      >
        {conversationQuery.isLoading ? (
          <Box sx={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100%" }}>
            <CircularProgress />
          </Box>
        ) : messages.length === 0 ? (
          <Box sx={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", opacity: 0.7 }}>
            <ChatIcon sx={{ fontSize: 64, mb: 2, opacity: 0.5 }} />
            <Typography variant="h6" color="text.secondary">
              No messages yet
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Start the conversation with your team!
            </Typography>
          </Box>
        ) : (
          <Stack spacing={1}>
            {messages.map((msg) => (
              <MessageBubble
                key={msg.id}
                message={msg}
                isOwn={msg.is_own_message}
                onReaction={(emoji, hasReacted) => handleReaction(msg.id, emoji, hasReacted)}
                onReply={() => setReplyingTo(msg)}
                onPin={() => handlePinMessage(msg.id)}
                onBookmark={() => handleBookmarkMessage(msg.id)}
                onViewEditHistory={() => handleViewEditHistory(msg)}
                onImageClick={() => handleImageClick(msg.id)}
                isPinned={pinnedMessages.some(p => p.message_id === msg.id)}
                readBy={getReadByForMessage(msg.id)}
                currentUserId={user?.id}
                poll={conversationPolls.find(p => p.message_id === msg.id)}
                onPollUpdate={(updatedPoll) => {
                  setConversationPolls(prev => prev.map(p => p.id === updatedPoll.id ? updatedPoll : p));
                }}
                formatTime={formatTime}
              />
            ))}
            <div ref={messagesEndRef} />
            
            {/* Typing Indicator */}
            {conversationId && (() => {
              const typingUsers = getTypingUsersForConversation(conversationId);
              if (typingUsers.length === 0) return null;
              const names = typingUsers.map(t => t.username).join(', ');
              return (
                <Box 
                  sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: 1.5, 
                    px: 2, 
                    py: 1,
                    bgcolor: 'action.hover',
                    borderRadius: 2,
                    maxWidth: 'fit-content',
                  }}
                >
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.4, px: 1, py: 0.5, bgcolor: 'background.paper', borderRadius: 2 }}>
                    {[0, 1, 2].map((i) => (
                      <Box 
                        key={i}
                        sx={{ 
                          width: 8, 
                          height: 8, 
                          borderRadius: '50%', 
                          bgcolor: 'primary.main', 
                          animation: 'typingBounce 1.4s infinite ease-in-out',
                          animationDelay: `${i * 0.15}s`,
                          '@keyframes typingBounce': {
                            '0%, 60%, 100%': { transform: 'translateY(0)' },
                            '30%': { transform: 'translateY(-4px)' },
                          },
                        }} 
                      />
                    ))}
                  </Box>
                  <Typography variant="body2" color="text.secondary" fontWeight={500}>
                    {typingUsers.length === 1 ? `${names} is typing...` : `${names} are typing...`}
                  </Typography>
                </Box>
              );
            })()}
          </Stack>
        )}
      </Paper>

      {/* Upload Progress */}
      {uploadProgress !== null && (
        <Box sx={{ px: 2, py: 1 }}>
          <Typography variant="caption" color="text.secondary">Uploading file...</Typography>
          <LinearProgress variant="determinate" value={uploadProgress} />
        </Box>
      )}

      {/* Reply Preview */}
      {replyingTo && (
        <Box sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          gap: 1, 
          px: 2, 
          py: 1, 
          mt: 1,
          bgcolor: 'action.hover',
          borderLeft: 3,
          borderColor: 'primary.main',
          borderRadius: 1,
        }}>
          <ReplyIcon fontSize="small" color="primary" />
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography variant="caption" color="primary" fontWeight={500}>
              Replying to {replyingTo.sender_username}
            </Typography>
            <Typography variant="body2" color="text.secondary" noWrap>
              {replyingTo.content}
            </Typography>
          </Box>
          <IconButton size="small" onClick={() => setReplyingTo(null)}>
            <CloseIcon fontSize="small" />
          </IconButton>
        </Box>
      )}

      {/* Message Input */}
      <Paper
        sx={{
          mt: 2,
          p: 2,
          border: `1px solid ${alpha(theme.palette.divider, 0.1)}`,
          borderRadius: 2,
          position: 'relative',
        }}
      >
        {/* Mention Suggestions */}
        {showMentionSuggestions && mentionSuggestions.length > 0 && (
          <Paper
            sx={{
              position: 'absolute',
              bottom: '100%',
              left: 0,
              right: 0,
              mb: 0.5,
              maxHeight: 200,
              overflowY: 'auto',
              zIndex: 10,
            }}
            elevation={3}
          >
            <List dense>
              {mentionSuggestions.map((participant) => (
                <ListItemButton
                  key={participant.user_id}
                  onClick={() => insertMention(participant)}
                >
                  <ListItemAvatar>
                    <Avatar src={participant.avatar_url} sx={{ width: 28, height: 28 }}>
                      {participant.username.charAt(0).toUpperCase()}
                    </Avatar>
                  </ListItemAvatar>
                  <ListItemText
                    primary={participant.username}
                    secondary={participant.first_name}
                  />
                </ListItemButton>
              ))}
            </List>
          </Paper>
        )}

        <TextField
          fullWidth
          multiline
          maxRows={4}
          inputRef={inputRef}
          placeholder={replyingTo ? "Type your reply... (use @ to mention)" : "Type a message... (use @ to mention)"}
          value={newMessage}
          onChange={handleInputChange}
          onKeyPress={handleKeyPress}
          disabled={sendMessageMutation.isPending || uploadProgress !== null}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start">
                <input
                  type="file"
                  ref={fileInputRef}
                  onChange={handleFileUpload}
                  style={{ display: 'none' }}
                  accept="image/*,video/*,audio/*,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.md,.zip,.rar,.7z,.tar,.gz,.py,.js,.ts,.jsx,.tsx,.java,.c,.cpp,.h,.cs,.go,.rs,.rb,.php,.swift,.kt,.html,.css,.json,.xml,.yaml,.yml,.sql,.apk,.aab,.ipa,.exe,.dll,.so,.pcap,.pcapng,.yar,.yara,.db,.sqlite,.log,*"
                />
                <Tooltip title="Attach file">
                  <IconButton 
                    onClick={() => fileInputRef.current?.click()}
                    disabled={sendMessageMutation.isPending || uploadProgress !== null}
                    size="small"
                  >
                    <AttachIcon />
                  </IconButton>
                </Tooltip>
                <IconButton
                  onClick={(e) => {
                    setEmojiPickerAnchor(e.currentTarget);
                    setShowEmojiPicker(true);
                  }}
                  disabled={sendMessageMutation.isPending || uploadProgress !== null}
                  size="small"
                >
                  <EmojiIcon />
                </IconButton>
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                <IconButton
                  onClick={handleSendMessage}
                  disabled={!newMessage.trim() || sendMessageMutation.isPending || uploadProgress !== null}
                  color="primary"
                  sx={{
                    bgcolor: newMessage.trim() ? alpha(theme.palette.primary.main, 0.1) : "transparent",
                    "&:hover": {
                      bgcolor: alpha(theme.palette.primary.main, 0.2),
                    },
                  }}
                >
                  {sendMessageMutation.isPending ? (
                    <CircularProgress size={20} />
                  ) : (
                    <SendIcon />
                  )}
                </IconButton>
              </InputAdornment>
            ),
          }}
          sx={{
            "& .MuiOutlinedInput-root": {
              borderRadius: 2,
            },
          }}
        />
      </Paper>

      {/* Emoji Picker Popover */}
      <Popover
        open={showEmojiPicker}
        anchorEl={emojiPickerAnchor}
        onClose={() => {
          setShowEmojiPicker(false);
          setEmojiPickerAnchor(null);
        }}
        anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
        transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <EmojiPicker
          onSelect={(emoji) => {
            setNewMessage(prev => prev + emoji);
            inputRef.current?.focus();
          }}
          onClose={() => {
            setShowEmojiPicker(false);
            setEmojiPickerAnchor(null);
          }}
        />
      </Popover>

      {/* Message Search Dialog */}
      {conversationId && (
        <MessageSearchDialog
          open={showMessageSearch}
          onClose={() => setShowMessageSearch(false)}
          conversationId={conversationId}
          onResultClick={() => {}}
        />
      )}

      {/* Poll Creator Dialog */}
      {conversationId && (
        <PollCreator
          open={showPollCreator}
          onClose={() => setShowPollCreator(false)}
          conversationId={conversationId}
          onPollCreated={handlePollCreated}
        />
      )}

      {/* Edit History Dialog */}
      <EditHistoryDialog
        open={showEditHistoryDialog}
        onClose={() => {
          setShowEditHistoryDialog(false);
          setEditHistoryMessageId(null);
          setEditHistoryContent('');
        }}
        messageId={editHistoryMessageId}
        currentContent={editHistoryContent}
      />

      {/* Bookmarks Dialog */}
      <BookmarksDialog
        open={showBookmarksDialog}
        onClose={() => setShowBookmarksDialog(false)}
        onNavigateToMessage={handleNavigateToBookmark}
      />

      {/* Image Gallery */}
      <ImageGallery
        images={getConversationImages()}
        open={imageGalleryOpen}
        onClose={() => setImageGalleryOpen(false)}
        initialIndex={imageGalleryIndex}
      />
    </Box>
  );
}

// Message Bubble Component
function MessageBubble({ 
  message, 
  isOwn,
  onReaction,
  onReply,
  onPin,
  onBookmark,
  onViewEditHistory,
  onImageClick,
  isPinned,
  readBy,
  currentUserId,
  poll,
  onPollUpdate,
  formatTime,
}: { 
  message: SocialMessage; 
  isOwn: boolean;
  onReaction: (emoji: string, hasReacted: boolean) => void;
  onReply: () => void;
  onPin: () => void;
  onBookmark: () => void;
  onViewEditHistory: () => void;
  onImageClick: () => void;
  isPinned: boolean;
  readBy: ReadReceiptInfo[];
  currentUserId?: number;
  poll?: PollResponse;
  onPollUpdate?: (poll: PollResponse) => void;
  formatTime: (dateStr: string) => string;
}) {
  const theme = useTheme();
  const [emojiAnchor, setEmojiAnchor] = useState<HTMLElement | null>(null);
  const [hovering, setHovering] = useState(false);

  const isImage = message.attachment_data?.file_type?.startsWith('image/');
  const fileInfo = message.attachment_data?.file_name 
    ? getFileTypeInfo(message.attachment_data.file_name, message.attachment_data.file_type)
    : null;
  const hasReactions = message.reactions && Object.keys(message.reactions).length > 0;

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: isOwn ? 'flex-end' : 'flex-start',
        mb: 1.5,
      }}
      onMouseEnter={() => setHovering(true)}
      onMouseLeave={() => setHovering(false)}
    >
      {/* Reply Preview */}
      {message.reply_to && (
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            gap: 0.5,
            px: 1.5,
            py: 0.5,
            ml: isOwn ? 0 : 5,
            mr: isOwn ? 0 : 'auto',
            bgcolor: 'action.hover',
            borderRadius: 1,
            borderLeft: 2,
            borderColor: 'primary.main',
            maxWidth: '60%',
            mb: 0.5,
          }}
        >
          <ReplyIcon fontSize="small" sx={{ opacity: 0.7 }} />
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="caption" fontWeight={500} color="primary">
              {message.reply_to.sender_username}
            </Typography>
            <Typography variant="caption" color="text.secondary" noWrap display="block">
              {message.reply_to.is_deleted ? 'This message was deleted' : message.reply_to.content_preview}
            </Typography>
          </Box>
        </Box>
      )}

      <Box sx={{ display: 'flex', alignItems: isOwn ? 'flex-end' : 'flex-start' }}>
        {!isOwn && (
          <Avatar
            src={message.sender_avatar_url}
            sx={{ width: 32, height: 32, mr: 1, bgcolor: 'primary.main' }}
          >
            {message.sender_username?.charAt(0).toUpperCase()}
          </Avatar>
        )}
        
        <Box sx={{ position: 'relative' }}>
          <Paper
            elevation={0}
            sx={{
              px: 2,
              py: 1,
              maxWidth: '100%',
              minWidth: 100,
              bgcolor: message.is_deleted ? 'action.disabledBackground' : (isOwn ? 'primary.main' : 'action.hover'),
              color: message.is_deleted ? 'text.disabled' : (isOwn ? 'primary.contrastText' : 'text.primary'),
              borderRadius: 2,
              borderTopLeftRadius: !isOwn ? 0 : 16,
              borderTopRightRadius: isOwn ? 0 : 16,
              fontStyle: message.is_deleted ? 'italic' : 'normal',
            }}
          >
            {!isOwn && !message.is_deleted && (
              <Typography variant="caption" sx={{ fontWeight: 500, display: 'block', mb: 0.5 }}>
                {message.sender_first_name || message.sender_username}
              </Typography>
            )}

            {/* File Attachment */}
            {message.message_type === 'file' && message.attachment_data && !message.is_deleted && (
              <Box sx={{ mb: 1 }}>
                {isImage ? (
                  <Box onClick={onImageClick} sx={{ cursor: 'pointer' }}>
                    <Box
                      component="img"
                      src={message.attachment_data.thumbnail_url || message.attachment_data.file_url}
                      alt={message.attachment_data.file_name}
                      sx={{
                        maxWidth: '100%',
                        maxHeight: 200,
                        borderRadius: 1,
                        transition: 'transform 0.2s',
                        '&:hover': { transform: 'scale(1.02)' },
                      }}
                    />
                  </Box>
                ) : (
                  <Box
                    component="a"
                    href={message.attachment_data.file_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    download
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1.5,
                      p: 1.5,
                      bgcolor: isOwn ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.05)',
                      borderRadius: 1,
                      textDecoration: 'none',
                      color: 'inherit',
                      border: '1px solid',
                      borderColor: isOwn ? 'rgba(255,255,255,0.2)' : 'divider',
                      '&:hover': { bgcolor: isOwn ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.08)' },
                    }}
                  >
                    <Box
                      sx={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: 40,
                        height: 40,
                        borderRadius: 1,
                        bgcolor: fileInfo?.color || '#757575',
                        color: 'white',
                        flexShrink: 0,
                      }}
                    >
                      {fileInfo?.icon || <FileIcon />}
                    </Box>
                    <Box sx={{ minWidth: 0, flex: 1 }}>
                      <Typography variant="body2" fontWeight={500} noWrap>
                        {message.attachment_data.file_name}
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="caption" sx={{ opacity: 0.7, bgcolor: isOwn ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.05)', px: 0.75, py: 0.25, borderRadius: 0.5 }}>
                          {fileInfo?.label || 'File'}
                        </Typography>
                        {message.attachment_data.file_size && (
                          <Typography variant="caption" sx={{ opacity: 0.7 }}>
                            {formatFileSize(message.attachment_data.file_size)}
                          </Typography>
                        )}
                      </Box>
                    </Box>
                  </Box>
                )}
              </Box>
            )}

            {/* Poll Display */}
            {message.message_type === 'poll' && poll && !message.is_deleted && (
              <Box sx={{ mt: 1 }}>
                <PollDisplay poll={poll} onUpdate={onPollUpdate} compact />
              </Box>
            )}

            {/* Message Content with Markdown */}
            {(message.message_type !== 'file' && message.message_type !== 'poll' || message.is_deleted || (message.message_type === 'poll' && !poll)) && (
              <Box sx={{ '& > span': { wordBreak: 'break-word' } }}>
                <MarkdownRenderer content={message.content} currentUserId={currentUserId} />
              </Box>
            )}

            {/* Pinned Indicator */}
            {isPinned && (
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5, opacity: 0.7 }}>
                <PinIcon sx={{ fontSize: 12 }} />
                <Typography variant="caption">Pinned</Typography>
              </Box>
            )}

            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mt: 0.5 }}>
              <Typography variant="caption" sx={{ opacity: 0.7 }}>
                {formatTime(message.created_at)}
                {message.is_edited && ' (edited)'}
              </Typography>
              
              {/* Read receipts for own messages */}
              {isOwn && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 1 }}>
                  {readBy.length > 0 ? (
                    <Tooltip title={`Seen by ${readBy.map(r => r.username).join(', ')}`}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        <ReadIcon sx={{ fontSize: 14, color: 'info.main' }} />
                        {readBy.length <= 3 ? (
                          <AvatarGroup max={3} sx={{ '& .MuiAvatar-root': { width: 16, height: 16, fontSize: 10 } }}>
                            {readBy.map(r => (
                              <Avatar key={r.user_id} src={r.avatar_url} sx={{ width: 16, height: 16 }}>
                                {r.username.charAt(0)}
                              </Avatar>
                            ))}
                          </AvatarGroup>
                        ) : (
                          <Typography variant="caption" sx={{ opacity: 0.7 }}>{readBy.length}</Typography>
                        )}
                      </Box>
                    </Tooltip>
                  ) : (
                    <Tooltip title="Sent">
                      <SentIcon sx={{ fontSize: 14, opacity: 0.6 }} />
                    </Tooltip>
                  )}
                </Box>
              )}
            </Box>
          </Paper>

          {/* Message Actions */}
          {hovering && !message.is_deleted && (
            <Box
              sx={{
                position: 'absolute',
                top: -8,
                [isOwn ? 'left' : 'right']: -8,
                display: 'flex',
                gap: 0.25,
                bgcolor: 'background.paper',
                borderRadius: 1,
                boxShadow: 1,
                p: 0.25,
              }}
            >
              <Tooltip title="React">
                <IconButton size="small" onClick={(e) => setEmojiAnchor(e.currentTarget)}>
                  <EmojiIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Reply">
                <IconButton size="small" onClick={onReply}>
                  <ReplyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title={isPinned ? "Unpin" : "Pin"}>
                <IconButton size="small" onClick={onPin}>
                  {isPinned ? <PinIcon fontSize="small" color="primary" /> : <PinOutlinedIcon fontSize="small" />}
                </IconButton>
              </Tooltip>
              <Tooltip title="Bookmark">
                <IconButton size="small" onClick={onBookmark}>
                  <BookmarkOutlineIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              {message.is_edited && (
                <Tooltip title="View Edit History">
                  <IconButton size="small" onClick={onViewEditHistory}>
                    <HistoryIcon fontSize="small" />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          )}

          {/* Emoji Picker Popover */}
          <Popover
            open={Boolean(emojiAnchor)}
            anchorEl={emojiAnchor}
            onClose={() => setEmojiAnchor(null)}
            anchorOrigin={{ vertical: 'top', horizontal: 'center' }}
            transformOrigin={{ vertical: 'bottom', horizontal: 'center' }}
          >
            <Box sx={{ display: 'flex', gap: 0.5, p: 1 }}>
              {COMMON_EMOJIS.map((emoji) => {
                const reaction = message.reactions?.[emoji];
                return (
                  <IconButton
                    key={emoji}
                    size="small"
                    onClick={() => {
                      onReaction(emoji, reaction?.has_reacted || false);
                      setEmojiAnchor(null);
                    }}
                    sx={{
                      fontSize: '1.2rem',
                      bgcolor: reaction?.has_reacted ? 'primary.light' : 'transparent',
                    }}
                  >
                    {emoji}
                  </IconButton>
                );
              })}
            </Box>
          </Popover>
        </Box>
      </Box>

      {/* Reactions Display */}
      {hasReactions && (
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: 0.5,
            mt: 0.5,
            ml: isOwn ? 0 : 5,
          }}
        >
          {Object.entries(message.reactions!).map(([emoji, info]) => (
            <Tooltip key={emoji} title={info.users.join(', ')}>
              <Chip
                label={`${emoji} ${info.count}`}
                size="small"
                onClick={() => onReaction(emoji, info.has_reacted)}
                sx={{
                  height: 24,
                  fontSize: '0.75rem',
                  bgcolor: info.has_reacted ? 'primary.light' : 'action.hover',
                  cursor: 'pointer',
                  '&:hover': { bgcolor: info.has_reacted ? 'primary.main' : 'action.selected' },
                }}
              />
            </Tooltip>
          ))}
        </Box>
      )}
    </Box>
  );
}
