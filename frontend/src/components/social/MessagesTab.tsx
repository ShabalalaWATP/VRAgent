import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemAvatar,
  ListItemText,
  Avatar,
  TextField,
  IconButton,
  CircularProgress,
  Alert,
  Badge,
  Paper,
  Divider,
  InputAdornment,
  Button,
  Chip,
  Tooltip,
  Popover,
  Menu,
  MenuItem,
  LinearProgress,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Collapse,
  Checkbox,
  ListItemButton,
  ListItemSecondaryAction,
  AvatarGroup,
  Autocomplete,
  Snackbar,
} from '@mui/material';
import {
  Send as SendIcon,
  ArrowBack as BackIcon,
  Chat as ChatIcon,
  Group as GroupIcon,
  Add as AddIcon,
  Settings as SettingsIcon,
  AttachFile as AttachIcon,
  EmojiEmotions as EmojiIcon,
  Reply as ReplyIcon,
  Close as CloseIcon,
  InsertDriveFile as FileIcon,
  Image as ImageIcon,
  CloudUpload as UploadIcon,
  Circle as CircleIcon,
  PushPin as PinIcon,
  PushPinOutlined as PinOutlinedIcon,
  Forward as ForwardIcon,
  DoneAll as ReadIcon,
  Done as SentIcon,
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  MoreVert as MoreIcon,
  Search as SearchIcon,
  Poll as PollIcon,
  NotificationsOff as MuteIcon,
  Notifications as UnmuteIcon,
  Delete as DeleteIcon,
  ExitToApp as LeaveIcon,
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
} from '@mui/icons-material';
import {
  socialApi,
  ConversationSummary,
  ConversationDetail,
  SocialMessage,
  UnreadCountResponse,
  ReactionSummary,
  AttachmentData,
  PinnedMessageInfo,
  ReadReceiptInfo,
  ConversationParticipant,
  PollResponse,
  MessageSearchResult,
  MuteStatusResponse,
} from '../../api/client';
import { useAuth } from '../../contexts/AuthContext';
import { useChatWebSocket, ConnectionStatus, TypingUser, QueuedMessage } from '../../hooks/useChatWebSocket';
import CreateGroupDialog from './CreateGroupDialog';
import GroupSettingsDialog from './GroupSettingsDialog';
import { MarkdownRenderer } from './MarkdownRenderer';
import { EmojiPicker } from './EmojiPicker';
import { PollCreator } from './PollCreator';
import { PollDisplay } from './PollDisplay';
import { MessageSearchDialog } from './MessageSearchDialog';
import { BookmarksDialog } from './BookmarksDialog';
import { EditHistoryDialog } from './EditHistoryDialog';
import { ImageGallery } from './ImageGallery';
import { OfflineQueueIndicator } from './OfflineQueueIndicator';

interface MessagesTabProps {
  unreadCounts: UnreadCountResponse | null;
  onRefresh: () => void;
}

// Common emoji reactions
const COMMON_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🔥', '👏', '🎉'];

// File type detection and icons
const getFileTypeInfo = (filename: string, mimeType?: string): { icon: React.ReactNode; color: string; label: string } => {
  const ext = filename.toLowerCase().split('.').pop() || '';
  
  // Images
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'tif'].includes(ext)) {
    return { icon: <ImageIcon />, color: '#4CAF50', label: 'Image' };
  }
  
  // PDFs
  if (ext === 'pdf') {
    return { icon: <PdfIcon />, color: '#F44336', label: 'PDF' };
  }
  
  // Word documents
  if (['doc', 'docx', 'odt', 'rtf'].includes(ext)) {
    return { icon: <DocIcon />, color: '#2196F3', label: 'Document' };
  }
  
  // Spreadsheets
  if (['xls', 'xlsx', 'ods', 'csv'].includes(ext)) {
    return { icon: <SpreadsheetIcon />, color: '#4CAF50', label: 'Spreadsheet' };
  }
  
  // Presentations
  if (['ppt', 'pptx', 'odp'].includes(ext)) {
    return { icon: <PresentationIcon />, color: '#FF9800', label: 'Presentation' };
  }
  
  // Code files
  if (['py', 'js', 'ts', 'jsx', 'tsx', 'java', 'c', 'cpp', 'h', 'cs', 'go', 'rs', 'rb', 'php', 'swift', 'kt', 'scala', 'html', 'css', 'scss', 'vue', 'svelte', 'sql', 'sh', 'bash', 'ps1', 'yaml', 'yml', 'json', 'xml', 'toml', 'ini', 'cfg', 'dockerfile', 'tf', 'proto', 'graphql'].includes(ext)) {
    return { icon: <CodeIcon />, color: '#9C27B0', label: 'Code' };
  }
  
  // Archives
  if (['zip', 'tar', 'gz', '7z', 'rar', 'tgz', 'bz2', 'xz'].includes(ext)) {
    return { icon: <ArchiveIcon />, color: '#795548', label: 'Archive' };
  }
  
  // Android files
  if (['apk', 'aab', 'dex', 'smali'].includes(ext)) {
    return { icon: <AndroidIcon />, color: '#3DDC84', label: 'Android' };
  }
  
  // iOS files
  if (['ipa', 'xib', 'storyboard', 'plist'].includes(ext)) {
    return { icon: <AppleIcon />, color: '#007AFF', label: 'iOS' };
  }
  
  // Binary/Executable files
  if (['exe', 'dll', 'so', 'dylib', 'elf', 'bin', 'msi', 'deb', 'rpm', 'dmg', 'class', 'jar', 'wasm'].includes(ext)) {
    return { icon: <BinaryIcon />, color: '#607D8B', label: 'Binary' };
  }
  
  // Security/Forensics files
  if (['pcap', 'pcapng', 'mem', 'dmp', 'yar', 'yara', 'rules', 'evtx', 'evt'].includes(ext)) {
    return { icon: <SecurityIcon />, color: '#FF5722', label: 'Security' };
  }
  
  // Database files
  if (['db', 'sqlite', 'sqlite3', 'sql'].includes(ext)) {
    return { icon: <DataIcon />, color: '#00BCD4', label: 'Database' };
  }
  
  // Text files
  if (['txt', 'md', 'log'].includes(ext)) {
    return { icon: <TextIcon />, color: '#9E9E9E', label: 'Text' };
  }
  
  // Default
  return { icon: <FileIcon />, color: '#757575', label: 'File' };
};

// Format file size helper
const formatFileSize = (bytes: number): string => {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
};

export default function MessagesTab({ unreadCounts, onRefresh }: MessagesTabProps) {
  const { user } = useAuth();
  const [conversations, setConversations] = useState<ConversationSummary[]>([]);
  const [selectedConversation, setSelectedConversation] = useState<ConversationDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMessages, setLoadingMessages] = useState(false);
  const [error, setError] = useState('');
  const [newMessage, setNewMessage] = useState('');
  const [sending, setSending] = useState(false);
  const [showCreateGroup, setShowCreateGroup] = useState(false);
  const [showGroupSettings, setShowGroupSettings] = useState(false);
  const [replyingTo, setReplyingTo] = useState<SocialMessage | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [isTyping, setIsTyping] = useState(false);
  // New state for pinning, forwarding, read receipts, mentions
  const [pinnedMessages, setPinnedMessages] = useState<PinnedMessageInfo[]>([]);
  const [showPinnedPanel, setShowPinnedPanel] = useState(false);
  const [showForwardDialog, setShowForwardDialog] = useState(false);
  const [forwardingMessage, setForwardingMessage] = useState<SocialMessage | null>(null);
  const [selectedForwardTargets, setSelectedForwardTargets] = useState<number[]>([]);
  const [readReceipts, setReadReceipts] = useState<ReadReceiptInfo[]>([]);
  const [mentionSuggestions, setMentionSuggestions] = useState<ConversationParticipant[]>([]);
  const [showMentionSuggestions, setShowMentionSuggestions] = useState(false);
  const [mentionAnchor, setMentionAnchor] = useState<HTMLElement | null>(null);
  const [cursorPosition, setCursorPosition] = useState(0);
  // New state for search, polls, emojis, mute
  const [showMessageSearch, setShowMessageSearch] = useState(false);
  const [showEmojiPicker, setShowEmojiPicker] = useState(false);
  const [showPollCreator, setShowPollCreator] = useState(false);
  const [conversationPolls, setConversationPolls] = useState<PollResponse[]>([]);
  const [muteStatus, setMuteStatus] = useState<MuteStatusResponse | null>(null);
  const [emojiPickerAnchor, setEmojiPickerAnchor] = useState<HTMLElement | null>(null);
  // State for delete conversation
  const [conversationMenuAnchor, setConversationMenuAnchor] = useState<HTMLElement | null>(null);
  const [conversationMenuTarget, setConversationMenuTarget] = useState<ConversationSummary | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<ConversationSummary | null>(null);
  const [deleting, setDeleting] = useState(false);
  // State for bookmarks, edit history, image gallery
  const [showBookmarksDialog, setShowBookmarksDialog] = useState(false);
  const [showEditHistoryDialog, setShowEditHistoryDialog] = useState(false);
  const [editHistoryMessageId, setEditHistoryMessageId] = useState<number | null>(null);
  const [editHistoryContent, setEditHistoryContent] = useState('');
  const [imageGalleryOpen, setImageGalleryOpen] = useState(false);
  const [imageGalleryIndex, setImageGalleryIndex] = useState(0);
  const [queueSnackbar, setQueueSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success',
  });
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // WebSocket connection
  const {
    status: wsStatus,
    sendTypingIndicator,
    sendViewingConversation,
    sendReadReceipt,
    getTypingUsersForConversation,
    isUserOnline,
    isOnline,
    messageQueue,
    queueMessage,
    removeQueuedMessage,
    retryQueuedMessage,
    processQueue,
    getQueuedMessagesForConversation,
  } = useChatWebSocket({
    onNewMessage: (message, conversationId) => {
      // Update conversation list
      loadConversations();
      // Update current conversation if it matches
      if (selectedConversation?.id === conversationId && !message.is_own_message) {
        setSelectedConversation(prev => prev ? {
          ...prev,
          messages: [...prev.messages, message],
          total_messages: prev.total_messages + 1,
        } : null);
        // Mark as read immediately
        sendReadReceipt(conversationId, message.id);
        // Also call API to persist
        socialApi.markConversationRead(conversationId).catch(() => {});
      }
    },
    onReadReceipt: (conversationId, userId, lastReadMessageId) => {
      // Update read receipts when someone reads messages
      if (selectedConversation?.id === conversationId) {
        setReadReceipts(prev => {
          const updated = prev.filter(r => r.user_id !== userId);
          // Find the user info from participants
          const participant = selectedConversation?.participants.find(p => p.user_id === userId);
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
    onMessageEdited: (messageId, conversationId, content, updatedAt) => {
      if (selectedConversation?.id === conversationId) {
        setSelectedConversation(prev => prev ? {
          ...prev,
          messages: prev.messages.map(m => 
            m.id === messageId ? { ...m, content, updated_at: updatedAt, is_edited: true } : m
          ),
        } : null);
      }
    },
    onMessageDeleted: (messageId, conversationId) => {
      if (selectedConversation?.id === conversationId) {
        setSelectedConversation(prev => prev ? {
          ...prev,
          messages: prev.messages.map(m => 
            m.id === messageId ? { ...m, is_deleted: true, content: 'This message was deleted' } : m
          ),
        } : null);
      }
    },
    onReactionAdded: (messageId, conversationId, emoji, userId, username) => {
      if (selectedConversation?.id === conversationId) {
        setSelectedConversation(prev => {
          if (!prev) return null;
          return {
            ...prev,
            messages: prev.messages.map(m => {
              if (m.id !== messageId) return m;
              const reactions = { ...(m.reactions || {}) };
              if (!reactions[emoji]) {
                reactions[emoji] = { emoji, count: 0, users: [], has_reacted: false };
              }
              if (!reactions[emoji].users.includes(username)) {
                reactions[emoji].count++;
                reactions[emoji].users.push(username);
                if (userId === user?.id) {
                  reactions[emoji].has_reacted = true;
                }
              }
              return { ...m, reactions };
            }),
          };
        });
      }
    },
    onReactionRemoved: (messageId, conversationId, emoji, userId, username) => {
      if (selectedConversation?.id === conversationId) {
        setSelectedConversation(prev => {
          if (!prev) return null;
          return {
            ...prev,
            messages: prev.messages.map(m => {
              if (m.id !== messageId) return m;
              const reactions = { ...(m.reactions || {}) };
              if (reactions[emoji]) {
                reactions[emoji].count--;
                reactions[emoji].users = reactions[emoji].users.filter(u => u !== username);
                if (userId === user?.id) {
                  reactions[emoji].has_reacted = false;
                }
                if (reactions[emoji].count <= 0) {
                  delete reactions[emoji];
                }
              }
              return { ...m, reactions };
            }),
          };
        });
      }
    },
    onConnectionChange: (_status) => {
      // Connection status handled by useChatWebSocket
    },
    onQueuedMessageSent: (messageId: string) => {
      setQueueSnackbar({ open: true, message: 'Queued message sent successfully', severity: 'success' });
    },
    onQueuedMessageFailed: (messageId: string, error: string) => {
      setQueueSnackbar({ open: true, message: `Failed to send queued message: ${error}`, severity: 'error' });
    },
  });

  const loadConversations = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const result = await socialApi.getConversations();
      setConversations(result.conversations);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load conversations');
    } finally {
      setLoading(false);
    }
  }, []);

  // Load pinned messages when conversation changes
  const loadPinnedMessages = useCallback(async (conversationId: number) => {
    try {
      const result = await socialApi.getPinnedMessages(conversationId);
      setPinnedMessages(result.pinned_messages);
    } catch (err) {
      console.error('Failed to load pinned messages:', err);
    }
  }, []);

  // Load read receipts
  const loadReadReceipts = useCallback(async (conversationId: number) => {
    try {
      const result = await socialApi.getConversationReadReceipts(conversationId);
      setReadReceipts(result.receipts);
    } catch (err) {
      console.error('Failed to load read receipts:', err);
    }
  }, []);

  // Load mute status
  const loadMuteStatus = useCallback(async (conversationId: number) => {
    try {
      const result = await socialApi.getMuteStatus(conversationId);
      setMuteStatus(result);
    } catch (err) {
      console.error('Failed to load mute status:', err);
    }
  }, []);

  // Load conversation polls
  const loadConversationPolls = useCallback(async (conversationId: number) => {
    try {
      const result = await socialApi.getConversationPolls(conversationId);
      setConversationPolls(result);
    } catch (err) {
      console.error('Failed to load polls:', err);
    }
  }, []);

  // Toggle mute
  const handleToggleMute = async (duration?: number) => {
    if (!selectedConversation) return;
    try {
      const newMuted = !muteStatus?.is_muted;
      const result = await socialApi.muteConversation(
        selectedConversation.id,
        newMuted,
        duration
      );
      setMuteStatus(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle mute');
    }
  };

  // Handle conversation context menu
  const handleConversationMenu = (event: React.MouseEvent<HTMLElement>, conv: ConversationSummary) => {
    event.stopPropagation();
    setConversationMenuAnchor(event.currentTarget);
    setConversationMenuTarget(conv);
  };

  const handleCloseConversationMenu = () => {
    setConversationMenuAnchor(null);
    setConversationMenuTarget(null);
  };

  // Handle delete conversation
  const handleDeleteClick = (conv: ConversationSummary) => {
    setDeleteTarget(conv);
    setShowDeleteConfirm(true);
    handleCloseConversationMenu();
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget) return;
    
    setDeleting(true);
    try {
      await socialApi.deleteConversation(deleteTarget.id);
      // Remove from list
      setConversations(prev => prev.filter(c => c.id !== deleteTarget.id));
      // If this was the selected conversation, go back to list
      if (selectedConversation?.id === deleteTarget.id) {
        setSelectedConversation(null);
      }
      onRefresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete conversation');
    } finally {
      setDeleting(false);
      setShowDeleteConfirm(false);
      setDeleteTarget(null);
    }
  };

  // Handle delete from conversation detail view
  const handleDeleteCurrentConversation = () => {
    if (selectedConversation) {
      // Create a summary-like object from detail (only need id and is_group for delete dialog)
      const target = {
        id: selectedConversation.id,
        name: selectedConversation.name,
        is_group: selectedConversation.is_group,
        participants: selectedConversation.participants,
        participant_count: selectedConversation.participant_count,
        created_at: selectedConversation.created_at,
        created_by: selectedConversation.created_by,
        my_role: selectedConversation.my_role,
        unread_count: 0,
      } as ConversationSummary;
      setDeleteTarget(target);
      setShowDeleteConfirm(true);
    }
  };

  // Handle poll creation
  const handlePollCreated = async () => {
    if (!selectedConversation) return;
    loadConversationPolls(selectedConversation.id);
    // Refresh messages to show poll
    const detail = await socialApi.getConversation(selectedConversation.id);
    setSelectedConversation(detail);
    loadConversations();
  };

  // Handle message search result click
  const handleSearchResultClick = async (result: MessageSearchResult) => {
    // Navigate to the conversation and message
    if (result.conversation_id !== selectedConversation?.id) {
      await openConversation(result.conversation_id);
    }
    // TODO: Scroll to the specific message
  };

  // Handle bookmark toggle
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

  // Handle view edit history
  const handleViewEditHistory = (message: SocialMessage) => {
    setEditHistoryMessageId(message.id);
    setEditHistoryContent(message.content);
    setShowEditHistoryDialog(true);
  };

  // Handle navigate to bookmarked message
  const handleNavigateToBookmark = async (conversationId: number, messageId: number) => {
    if (conversationId !== selectedConversation?.id) {
      await openConversation(conversationId);
    }
    // TODO: Scroll to specific message
  };

  // Get all images from conversation for gallery
  const getConversationImages = useCallback(() => {
    if (!selectedConversation) return [];
    return selectedConversation.messages
      .filter(m => m.message_type === 'file' && m.attachment_data?.file_type?.startsWith('image/'))
      .map(m => ({
        id: m.id,
        url: m.attachment_data!.file_url!,
        filename: m.attachment_data!.file_name || 'image',
        thumbnailUrl: m.attachment_data!.thumbnail_url,
        senderUsername: m.sender_username,
        createdAt: m.created_at,
      }));
  }, [selectedConversation]);

  // Handle image click to open gallery
  const handleImageClick = (messageId: number) => {
    const images = getConversationImages();
    const imageMessages = selectedConversation?.messages
      .filter(m => m.message_type === 'file' && m.attachment_data?.file_type?.startsWith('image/')) || [];
    const index = imageMessages.findIndex(m => m.id === messageId);
    if (index >= 0) {
      setImageGalleryIndex(index);
      setImageGalleryOpen(true);
    }
  };

  // Pin/Unpin a message
  const handlePinMessage = async (messageId: number) => {
    if (!selectedConversation) return;
    try {
      const isPinned = pinnedMessages.some(p => p.message_id === messageId);
      if (isPinned) {
        await socialApi.unpinMessage(selectedConversation.id, messageId);
        setPinnedMessages(prev => prev.filter(p => p.message_id !== messageId));
      } else {
        const pinned = await socialApi.pinMessage(selectedConversation.id, messageId);
        setPinnedMessages(prev => [...prev, pinned]);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to pin/unpin message');
    }
  };

  // Forward a message
  const handleForwardMessage = async () => {
    if (!forwardingMessage || selectedForwardTargets.length === 0) return;
    try {
      const result = await socialApi.forwardMessage(forwardingMessage.id, selectedForwardTargets);
      if (result.failed_count > 0) {
        setError(`Message forwarded to ${result.forwarded_to.length - result.failed_count} conversations, ${result.failed_count} failed`);
      }
      setShowForwardDialog(false);
      setForwardingMessage(null);
      setSelectedForwardTargets([]);
      loadConversations(); // Refresh to show forwarded messages
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to forward message');
    }
  };

  // Mention handling
  const handleMentionInput = (value: string, position: number) => {
    const textBeforeCursor = value.slice(0, position);
    const mentionMatch = textBeforeCursor.match(/@(\w*)$/);
    
    if (mentionMatch && selectedConversation) {
      const query = mentionMatch[1].toLowerCase();
      const suggestions = selectedConversation.participants.filter(p =>
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

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  // Load pinned messages and read receipts when conversation is selected
  useEffect(() => {
    if (selectedConversation) {
      loadPinnedMessages(selectedConversation.id);
      loadReadReceipts(selectedConversation.id);
      loadMuteStatus(selectedConversation.id);
      loadConversationPolls(selectedConversation.id);
    } else {
      setPinnedMessages([]);
      setReadReceipts([]);
      setMuteStatus(null);
      setConversationPolls([]);
    }
  }, [selectedConversation?.id, loadPinnedMessages, loadReadReceipts, loadMuteStatus, loadConversationPolls]);

  // Track which conversation is being viewed
  useEffect(() => {
    if (selectedConversation) {
      sendViewingConversation(selectedConversation.id);
    } else {
      sendViewingConversation(null);
    }
  }, [selectedConversation?.id, sendViewingConversation]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (selectedConversation) {
      scrollToBottom();
    }
  }, [selectedConversation?.messages]);

  // Handle typing indicator and mentions
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    const position = e.target.selectionStart || 0;
    setNewMessage(value);
    setCursorPosition(position);
    
    // Check for mentions
    handleMentionInput(value, position);
    
    if (!isTyping && selectedConversation) {
      setIsTyping(true);
      sendTypingIndicator(selectedConversation.id, true);
    }
    
    // Clear existing timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    
    // Stop typing after 2 seconds of no input
    typingTimeoutRef.current = setTimeout(() => {
      setIsTyping(false);
      if (selectedConversation) {
        sendTypingIndicator(selectedConversation.id, false);
      }
    }, 2000);
  };

  const openConversation = async (conversationId: number) => {
    setLoadingMessages(true);
    setError('');
    try {
      const detail = await socialApi.getConversation(conversationId);
      setSelectedConversation(detail);
      
      // Send viewing status via WebSocket
      sendViewingConversation(conversationId);
      
      // Mark conversation as read if there are messages
      if (detail.messages.length > 0) {
        const lastMessage = detail.messages[detail.messages.length - 1];
        sendReadReceipt(conversationId, lastMessage.id);
        socialApi.markConversationRead(conversationId).catch(() => {});
      }
      
      onRefresh(); // Refresh unread counts
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load conversation');
    } finally {
      setLoadingMessages(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newMessage.trim() || !selectedConversation || sending) return;

    setSending(true);
    const messageText = newMessage.trim();
    setNewMessage('');
    const replyToMsg = replyingTo;
    setReplyingTo(null);
    
    // Stop typing indicator
    setIsTyping(false);
    sendTypingIndicator(selectedConversation.id, false);

    try {
      let sentMessage: SocialMessage;
      
      if (replyToMsg) {
        sentMessage = await socialApi.replyToMessage(
          selectedConversation.id,
          replyToMsg.id,
          messageText
        );
      } else {
        sentMessage = await socialApi.sendMessage(selectedConversation.id, messageText);
      }
      
      setSelectedConversation({
        ...selectedConversation,
        messages: [...selectedConversation.messages, sentMessage],
        total_messages: selectedConversation.total_messages + 1,
      });
      // Update conversation list
      loadConversations();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send message');
      setNewMessage(messageText); // Restore message on error
      setReplyingTo(replyToMsg);
    } finally {
      setSending(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file || !selectedConversation) return;
    
    // Reset input
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }

    // File size validation (1GB max)
    const MAX_SIZE = 1024 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      setError(`File too large. Maximum size is 1GB. Your file is ${formatFileSize(file.size)}`);
      return;
    }

    // Get file info for display
    const fileInfo = getFileTypeInfo(file.name, file.type);
    setUploadProgress(0);
    
    try {
      // Upload file
      const uploadResult = await socialApi.uploadFile(file);
      setUploadProgress(100);
      
      // Send message with file attachment
      const attachmentData: AttachmentData = {
        file_name: uploadResult.filename,
        file_type: uploadResult.mime_type,
        file_size: uploadResult.file_size,
        file_url: uploadResult.file_url,
        thumbnail_url: uploadResult.thumbnail_url,
      };
      
      // Create appropriate message based on file type
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
      } else if (fileInfo.label === 'Binary') {
        messageContent = `Shared binary: ${uploadResult.filename}`;
      }
      
      const sentMessage = await socialApi.sendMessage(
        selectedConversation.id,
        messageContent,
        'file',
        attachmentData
      );
      
      setSelectedConversation({
        ...selectedConversation,
        messages: [...selectedConversation.messages, sentMessage],
        total_messages: selectedConversation.total_messages + 1,
      });
      
      loadConversations();
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Failed to upload file';
      // Provide more helpful error messages
      if (errorMsg.includes('not allowed')) {
        setError(`File type not supported. Try zipping the file first, or contact support if you need this file type added.`);
      } else if (errorMsg.includes('credentials')) {
        setError('Session expired. Please refresh the page and try again.');
      } else {
        setError(errorMsg);
      }
    } finally {
      setUploadProgress(null);
    }
  };

  const handleReaction = async (messageId: number, emoji: string, hasReacted: boolean) => {
    try {
      if (hasReacted) {
        await socialApi.removeReaction(messageId, emoji);
      } else {
        await socialApi.addReaction(messageId, emoji);
      }
      // The WebSocket will handle the UI update
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update reaction');
    }
  };

  const formatTime = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const isToday = date.toDateString() === now.toDateString();
    
    if (isToday) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const getOtherParticipant = (conv: ConversationSummary | ConversationDetail) => {
    return conv.participants.find(p => p.user_id !== user?.id);
  };

  const handleGroupCreated = (group: ConversationSummary) => {
    loadConversations();
    openConversation(group.id);
  };

  const handleGroupUpdated = () => {
    if (selectedConversation) {
      openConversation(selectedConversation.id);
    }
    loadConversations();
  };

  const handleLeftGroup = () => {
    setSelectedConversation(null);
    loadConversations();
    onRefresh();
  };

  const getConversationAvatar = (conv: ConversationSummary) => {
    if (conv.is_group) {
      return conv.avatar_url;
    }
    const other = conv.participants.find(p => p.user_id !== user?.id);
    return other?.avatar_url;
  };

  const getConversationName = (conv: ConversationSummary) => {
    if (conv.name) return conv.name;
    if (!conv.is_group) {
      const other = conv.participants.find(p => p.user_id !== user?.id);
      return other?.username || 'Unknown';
    }
    return 'Group Chat';
  };

  // Conversation List View
  if (!selectedConversation) {
    return (
      <Box sx={{ px: 3 }}>
        {/* Create Group Button */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Tooltip title="View Bookmarks">
            <IconButton onClick={() => setShowBookmarksDialog(true)} color="primary">
              <BookmarkIcon />
            </IconButton>
          </Tooltip>
          <Button
            variant="outlined"
            startIcon={<AddIcon />}
            onClick={() => setShowCreateGroup(true)}
          >
            New Group
          </Button>
        </Box>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
            {error}
          </Alert>
        )}

        {loading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : conversations.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <ChatIcon sx={{ fontSize: 64, color: 'text.disabled', mb: 2 }} />
            <Typography color="text.secondary">
              No conversations yet. Start chatting with your friends!
            </Typography>
          </Box>
        ) : (
          <List>
            {conversations.map((conv) => {
              const other = getOtherParticipant(conv);
              const unread = unreadCounts?.by_conversation[conv.id] || 0;
              
              return (
                <ListItem
                  key={conv.id}
                  onClick={() => openConversation(conv.id)}
                  sx={{
                    border: '1px solid',
                    borderColor: unread > 0 ? 'primary.main' : 'divider',
                    borderRadius: 1,
                    mb: 1,
                    cursor: 'pointer',
                    bgcolor: unread > 0 ? 'action.hover' : 'transparent',
                    '&:hover': { bgcolor: 'action.selected' },
                  }}
                >
                  <ListItemAvatar>
                    <Badge badgeContent={unread} color="primary" max={99}>
                      {conv.is_group ? (
                        <Avatar sx={{ bgcolor: 'secondary.main' }}>
                          <GroupIcon />
                        </Avatar>
                      ) : (
                        <Avatar src={getConversationAvatar(conv)} sx={{ bgcolor: 'primary.main' }}>
                          {other?.username?.charAt(0).toUpperCase() || '?'}
                        </Avatar>
                      )}
                    </Badge>
                  </ListItemAvatar>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="subtitle1" fontWeight={unread > 0 ? 600 : 400}>
                            {getConversationName(conv)}
                          </Typography>
                          {conv.is_group && (
                            <Chip 
                              label={`${conv.participant_count} members`} 
                              size="small" 
                              variant="outlined"
                              sx={{ height: 20, fontSize: '0.7rem' }}
                            />
                          )}
                        </Box>
                        {conv.last_message_at && (
                          <Typography variant="caption" color="text.secondary">
                            {formatTime(conv.last_message_at)}
                          </Typography>
                        )}
                      </Box>
                    }
                    secondary={
                      conv.last_message_preview ? (
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{
                            fontWeight: unread > 0 ? 500 : 400,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {conv.last_message_sender === user?.username ? 'You: ' : 
                           conv.is_group ? `${conv.last_message_sender}: ` : ''}
                          {conv.last_message_preview}
                        </Typography>
                      ) : (
                        <Typography variant="body2" color="text.disabled">
                          No messages yet
                        </Typography>
                      )
                    }
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      size="small"
                      onClick={(e) => handleConversationMenu(e, conv)}
                    >
                      <MoreIcon />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              );
            })}
          </List>
        )}

        {/* Conversation Context Menu */}
        <Menu
          anchorEl={conversationMenuAnchor}
          open={Boolean(conversationMenuAnchor)}
          onClose={handleCloseConversationMenu}
        >
          <MenuItem 
            onClick={() => conversationMenuTarget && handleDeleteClick(conversationMenuTarget)}
            sx={{ color: 'error.main' }}
          >
            {conversationMenuTarget?.is_group ? (
              <>
                <LeaveIcon sx={{ mr: 1 }} fontSize="small" />
                {conversationMenuTarget?.my_role === 'owner' ? 'Delete Group' : 'Leave Group'}
              </>
            ) : (
              <>
                <DeleteIcon sx={{ mr: 1 }} fontSize="small" />
                Delete Chat
              </>
            )}
          </MenuItem>
        </Menu>

        {/* Delete Confirmation Dialog */}
        <Dialog open={showDeleteConfirm} onClose={() => !deleting && setShowDeleteConfirm(false)}>
          <DialogTitle>
            {deleteTarget?.is_group 
              ? (deleteTarget?.my_role === 'owner' ? 'Delete Group?' : 'Leave Group?')
              : 'Delete Conversation?'
            }
          </DialogTitle>
          <DialogContent>
            <Typography>
              {deleteTarget?.is_group ? (
                deleteTarget?.my_role === 'owner' 
                  ? 'This will permanently delete the group and all messages for everyone. This cannot be undone.'
                  : 'You will leave this group. You can be re-added by an admin.'
              ) : (
                'This conversation will be removed from your list. The other person will still have their copy.'
              )}
            </Typography>
          </DialogContent>
          <DialogActions>
            <Button onClick={() => setShowDeleteConfirm(false)} disabled={deleting}>
              Cancel
            </Button>
            <Button 
              onClick={handleConfirmDelete} 
              color="error" 
              variant="contained"
              disabled={deleting}
            >
              {deleting ? <CircularProgress size={20} /> : (deleteTarget?.is_group ? (deleteTarget?.my_role === 'owner' ? 'Delete' : 'Leave') : 'Delete')}
            </Button>
          </DialogActions>
        </Dialog>

        {/* Create Group Dialog */}
        <CreateGroupDialog
          open={showCreateGroup}
          onClose={() => setShowCreateGroup(false)}
          onGroupCreated={handleGroupCreated}
        />

        {/* Bookmarks Dialog */}
        <BookmarksDialog
          open={showBookmarksDialog}
          onClose={() => setShowBookmarksDialog(false)}
          onNavigateToMessage={handleNavigateToBookmark}
        />
      </Box>
    );
  }

  // Conversation Detail View
  const other = getOtherParticipant(selectedConversation);
  const isGroupAdmin = selectedConversation.is_group && 
    (selectedConversation.my_role === 'owner' || selectedConversation.my_role === 'admin');

  // Get read receipt info for display
  const getReadByForMessage = (messageId: number) => {
    return readReceipts.filter(r => r.last_read_message_id >= messageId && r.user_id !== user?.id);
  };

  return (
    <Box sx={{ px: 3, display: 'flex', flexDirection: 'column', height: 'calc(100vh - 350px)', minHeight: 400 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
        <IconButton onClick={() => setSelectedConversation(null)}>
          <BackIcon />
        </IconButton>
        
        {selectedConversation.is_group ? (
          <>
            <Avatar sx={{ bgcolor: 'secondary.main' }}>
              <GroupIcon />
            </Avatar>
            <Box sx={{ flex: 1 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="subtitle1" fontWeight={500}>
                  {selectedConversation.name || 'Group Chat'}
                </Typography>
                <Chip 
                  label={`${selectedConversation.participant_count} members`} 
                  size="small" 
                  variant="outlined"
                  sx={{ height: 20, fontSize: '0.7rem' }}
                />
              </Box>
              {selectedConversation.description && (
                <Typography variant="caption" color="text.secondary">
                  {selectedConversation.description}
                </Typography>
              )}
            </Box>
            {/* Pinned Messages Button */}
            {pinnedMessages.length > 0 && (
              <Tooltip title={`${pinnedMessages.length} pinned message${pinnedMessages.length > 1 ? 's' : ''}`}>
                <IconButton onClick={() => setShowPinnedPanel(!showPinnedPanel)}>
                  <Badge badgeContent={pinnedMessages.length} color="primary">
                    <PinIcon />
                  </Badge>
                </IconButton>
              </Tooltip>
            )}
            {/* Search Messages */}
            <Tooltip title="Search Messages">
              <IconButton onClick={() => setShowMessageSearch(true)}>
                <SearchIcon />
              </IconButton>
            </Tooltip>
            {/* Create Poll */}
            <Tooltip title="Create Poll">
              <IconButton onClick={() => setShowPollCreator(true)}>
                <PollIcon />
              </IconButton>
            </Tooltip>
            {/* Mute Conversation */}
            <Tooltip title={muteStatus?.is_muted ? 'Unmute' : 'Mute'}>
              <IconButton onClick={() => handleToggleMute()}>
                {muteStatus?.is_muted ? <MuteIcon color="action" /> : <UnmuteIcon />}
              </IconButton>
            </Tooltip>
            <Tooltip title="Group Settings">
              <IconButton onClick={() => setShowGroupSettings(true)}>
                <SettingsIcon />
              </IconButton>
            </Tooltip>
            {/* Leave/Delete Group */}
            <Tooltip title={selectedConversation.my_role === 'owner' ? 'Delete Group' : 'Leave Group'}>
              <IconButton onClick={handleDeleteCurrentConversation} color="error">
                {selectedConversation.my_role === 'owner' ? <DeleteIcon /> : <LeaveIcon />}
              </IconButton>
            </Tooltip>
          </>
        ) : (
          <>
            <Avatar src={other?.avatar_url} sx={{ bgcolor: 'primary.main' }}>
              {other?.username?.charAt(0).toUpperCase() || '?'}
            </Avatar>
            <Box sx={{ flex: 1 }}>
              <Typography variant="subtitle1" fontWeight={500}>
                {other?.username || 'Unknown'}
              </Typography>
              {other?.first_name && (
                <Typography variant="caption" color="text.secondary">
                  {other.first_name} {other.last_name}
                </Typography>
              )}
            </Box>
            {/* Pinned Messages Button for DMs */}
            {pinnedMessages.length > 0 && (
              <Tooltip title={`${pinnedMessages.length} pinned message${pinnedMessages.length > 1 ? 's' : ''}`}>
                <IconButton onClick={() => setShowPinnedPanel(!showPinnedPanel)}>
                  <Badge badgeContent={pinnedMessages.length} color="primary">
                    <PinIcon />
                  </Badge>
                </IconButton>
              </Tooltip>
            )}
            {/* Search Messages */}
            <Tooltip title="Search Messages">
              <IconButton onClick={() => setShowMessageSearch(true)}>
                <SearchIcon />
              </IconButton>
            </Tooltip>
            {/* Create Poll */}
            <Tooltip title="Create Poll">
              <IconButton onClick={() => setShowPollCreator(true)}>
                <PollIcon />
              </IconButton>
            </Tooltip>
            {/* Mute Conversation */}
            <Tooltip title={muteStatus?.is_muted ? 'Unmute' : 'Mute'}>
              <IconButton onClick={() => handleToggleMute()}>
                {muteStatus?.is_muted ? <MuteIcon color="action" /> : <UnmuteIcon />}
              </IconButton>
            </Tooltip>
            {/* Delete Chat */}
            <Tooltip title="Delete Chat">
              <IconButton onClick={handleDeleteCurrentConversation} color="error">
                <DeleteIcon />
              </IconButton>
            </Tooltip>
          </>
        )}
      </Box>

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

      <Divider />

      {error && (
        <Alert severity="error" sx={{ my: 1 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      {/* Connection Status */}
      {wsStatus !== 'connected' && (
        <Chip
          icon={<CircleIcon sx={{ fontSize: 8 }} />}
          label={wsStatus === 'connecting' ? 'Connecting...' : 'Offline'}
          size="small"
          color={wsStatus === 'connecting' ? 'warning' : 'error'}
          sx={{ alignSelf: 'center', my: 1 }}
        />
      )}

      {/* Offline Queue Indicator */}
      <OfflineQueueIndicator
        isOnline={isOnline}
        queuedMessages={messageQueue}
        conversationId={selectedConversation.id}
        onRetry={retryQueuedMessage}
        onRemove={removeQueuedMessage}
        onProcessQueue={processQueue}
      />

      {/* Messages */}
      <Box sx={{ flex: 1, overflowY: 'auto', py: 2 }}>
        {loadingMessages ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
            <CircularProgress />
          </Box>
        ) : selectedConversation.messages.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 4 }}>
            <Typography color="text.secondary">
              No messages yet. Say hello!
            </Typography>
          </Box>
        ) : (
          selectedConversation.messages.map((msg) => (
            <MessageBubble 
              key={msg.id} 
              message={msg} 
              isOwn={msg.is_own_message}
              onReaction={(emoji, hasReacted) => handleReaction(msg.id, emoji, hasReacted)}
              onReply={() => setReplyingTo(msg)}
              onPin={() => handlePinMessage(msg.id)}
              onForward={() => {
                setForwardingMessage(msg);
                setShowForwardDialog(true);
              }}
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
            />
          ))
        )}
        <div ref={messagesEndRef} />
        
        {/* Typing Indicator */}
        {selectedConversation && (() => {
          const typingUsers = getTypingUsersForConversation(selectedConversation.id);
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
                mx: 1,
                mb: 1,
                maxWidth: 'fit-content',
              }}
            >
              <Box 
                sx={{ 
                  display: 'flex', 
                  alignItems: 'center',
                  gap: 0.4,
                  px: 1,
                  py: 0.5,
                  bgcolor: 'background.paper',
                  borderRadius: 2,
                }}
              >
                <Box 
                  sx={{ 
                    width: 8, 
                    height: 8, 
                    borderRadius: '50%', 
                    bgcolor: 'primary.main', 
                    animation: 'typingBounce 1.4s infinite ease-in-out',
                    '@keyframes typingBounce': {
                      '0%, 60%, 100%': { transform: 'translateY(0)' },
                      '30%': { transform: 'translateY(-4px)' },
                    },
                  }} 
                />
                <Box 
                  sx={{ 
                    width: 8, 
                    height: 8, 
                    borderRadius: '50%', 
                    bgcolor: 'primary.main', 
                    animation: 'typingBounce 1.4s infinite ease-in-out',
                    animationDelay: '0.15s',
                    '@keyframes typingBounce': {
                      '0%, 60%, 100%': { transform: 'translateY(0)' },
                      '30%': { transform: 'translateY(-4px)' },
                    },
                  }} 
                />
                <Box 
                  sx={{ 
                    width: 8, 
                    height: 8, 
                    borderRadius: '50%', 
                    bgcolor: 'primary.main', 
                    animation: 'typingBounce 1.4s infinite ease-in-out',
                    animationDelay: '0.3s',
                    '@keyframes typingBounce': {
                      '0%, 60%, 100%': { transform: 'translateY(0)' },
                      '30%': { transform: 'translateY(-4px)' },
                    },
                  }} 
                />
              </Box>
              <Typography variant="body2" color="text.secondary" fontWeight={500}>
                {typingUsers.length === 1 ? `${names} is typing...` : `${names} are typing...`}
              </Typography>
            </Box>
          );
        })()}
      </Box>

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
          bgcolor: 'action.hover',
          borderLeft: 3,
          borderColor: 'primary.main',
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
      <Box component="form" onSubmit={handleSendMessage} sx={{ pt: 2, position: 'relative' }}>
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
          inputRef={inputRef}
          placeholder={replyingTo ? 'Type your reply... (use @ to mention)' : 'Type a message... (use @ to mention)'}
          value={newMessage}
          onChange={handleInputChange}
          disabled={sending || uploadProgress !== null}
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
                <Tooltip title="Attach file (images, docs, code, APKs, archives, etc.)">
                  <IconButton 
                    onClick={() => fileInputRef.current?.click()}
                    disabled={sending || uploadProgress !== null}
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
                  disabled={sending || uploadProgress !== null}
                  size="small"
                  title="Insert emoji"
                >
                  <EmojiIcon />
                </IconButton>
              </InputAdornment>
            ),
            endAdornment: (
              <InputAdornment position="end">
                <IconButton
                  type="submit"
                  color="primary"
                  disabled={!newMessage.trim() || sending || uploadProgress !== null}
                >
                  {sending ? <CircularProgress size={24} /> : <SendIcon />}
                </IconButton>
              </InputAdornment>
            ),
          }}
        />
      </Box>

      {/* Forward Message Dialog */}
      <Dialog
        open={showForwardDialog}
        onClose={() => {
          setShowForwardDialog(false);
          setForwardingMessage(null);
          setSelectedForwardTargets([]);
        }}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ForwardIcon />
            Forward Message
          </Box>
        </DialogTitle>
        <DialogContent>
          {forwardingMessage && (
            <Paper sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }} elevation={0}>
              <Typography variant="caption" color="text.secondary">
                Message from {forwardingMessage.sender_username}
              </Typography>
              <Typography variant="body2">
                {forwardingMessage.content}
              </Typography>
            </Paper>
          )}
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Select conversations to forward to:
          </Typography>
          <List sx={{ maxHeight: 300, overflow: 'auto' }}>
            {conversations
              .filter(c => c.id !== selectedConversation?.id)
              .map((conv) => (
                <ListItem
                  key={conv.id}
                  dense
                  onClick={() => {
                    setSelectedForwardTargets(prev =>
                      prev.includes(conv.id)
                        ? prev.filter(id => id !== conv.id)
                        : [...prev, conv.id]
                    );
                  }}
                  sx={{ cursor: 'pointer' }}
                >
                  <Checkbox
                    checked={selectedForwardTargets.includes(conv.id)}
                    edge="start"
                  />
                  <ListItemAvatar>
                    {conv.is_group ? (
                      <Avatar sx={{ bgcolor: 'secondary.main' }}>
                        <GroupIcon />
                      </Avatar>
                    ) : (
                      <Avatar src={getConversationAvatar(conv)}>
                        {getConversationName(conv).charAt(0).toUpperCase()}
                      </Avatar>
                    )}
                  </ListItemAvatar>
                  <ListItemText primary={getConversationName(conv)} />
                </ListItem>
              ))}
          </List>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => {
            setShowForwardDialog(false);
            setForwardingMessage(null);
            setSelectedForwardTargets([]);
          }}>
            Cancel
          </Button>
          <Button
            variant="contained"
            onClick={handleForwardMessage}
            disabled={selectedForwardTargets.length === 0}
            startIcon={<ForwardIcon />}
          >
            Forward to {selectedForwardTargets.length} conversation{selectedForwardTargets.length !== 1 ? 's' : ''}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Group Settings Dialog */}
      {selectedConversation.is_group && (
        <GroupSettingsDialog
          open={showGroupSettings}
          onClose={() => setShowGroupSettings(false)}
          conversation={selectedConversation}
          onGroupUpdated={handleGroupUpdated}
          onLeftGroup={handleLeftGroup}
        />
      )}

      {/* Message Search Dialog */}
      <MessageSearchDialog
        open={showMessageSearch}
        onClose={() => setShowMessageSearch(false)}
        conversationId={selectedConversation.id}
        onResultClick={handleSearchResultClick}
      />

      {/* Poll Creator Dialog */}
      <PollCreator
        open={showPollCreator}
        onClose={() => setShowPollCreator(false)}
        conversationId={selectedConversation.id}
        onPollCreated={handlePollCreated}
      />

      {/* Emoji Picker Popover */}
      <Popover
        open={showEmojiPicker}
        anchorEl={emojiPickerAnchor}
        onClose={() => {
          setShowEmojiPicker(false);
          setEmojiPickerAnchor(null);
        }}
        anchorOrigin={{
          vertical: 'top',
          horizontal: 'center',
        }}
        transformOrigin={{
          vertical: 'bottom',
          horizontal: 'center',
        }}
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

      {/* Image Gallery */}
      <ImageGallery
        images={getConversationImages()}
        open={imageGalleryOpen}
        onClose={() => setImageGalleryOpen(false)}
        initialIndex={imageGalleryIndex}
      />

      {/* Queue Status Snackbar */}
      <Snackbar
        open={queueSnackbar.open}
        autoHideDuration={4000}
        onClose={() => setQueueSnackbar(prev => ({ ...prev, open: false }))}
      >
        <Alert
          severity={queueSnackbar.severity}
          onClose={() => setQueueSnackbar(prev => ({ ...prev, open: false }))}
        >
          {queueSnackbar.message}
        </Alert>
      </Snackbar>
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
  onForward,
  onBookmark,
  onViewEditHistory,
  onImageClick,
  isPinned,
  readBy,
  currentUserId,
  poll,
  onPollUpdate,
}: { 
  message: SocialMessage; 
  isOwn: boolean;
  onReaction: (emoji: string, hasReacted: boolean) => void;
  onReply: () => void;
  onPin: () => void;
  onForward: () => void;
  onBookmark: () => void;
  onViewEditHistory: () => void;
  onImageClick: () => void;
  isPinned: boolean;
  readBy: ReadReceiptInfo[];
  currentUserId?: number;
  poll?: PollResponse;
  onPollUpdate?: (poll: PollResponse) => void;
}) {
  const [emojiAnchor, setEmojiAnchor] = useState<HTMLElement | null>(null);
  const [hovering, setHovering] = useState(false);
  const [moreAnchor, setMoreAnchor] = useState<HTMLElement | null>(null);

  const formatTime = (dateStr: string) => {
    return new Date(dateStr).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  // Using the global formatFileSize helper defined above

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
                  <Box
                    onClick={(e) => {
                      e.preventDefault();
                      onImageClick();
                    }}
                    sx={{ display: 'block', cursor: 'pointer' }}
                  >
                    <Box
                      component="img"
                      src={message.attachment_data.thumbnail_url || message.attachment_data.file_url}
                      alt={message.attachment_data.file_name}
                      sx={{
                        maxWidth: '100%',
                        maxHeight: 200,
                        borderRadius: 1,
                        cursor: 'pointer',
                        transition: 'transform 0.2s, box-shadow 0.2s',
                        '&:hover': {
                          transform: 'scale(1.02)',
                          boxShadow: 3,
                        },
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
                      transition: 'all 0.2s',
                      '&:hover': {
                        bgcolor: isOwn ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.08)',
                      },
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
                      <Typography 
                        variant="body2" 
                        fontWeight={500}
                        sx={{ 
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {message.attachment_data.file_name}
                      </Typography>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography 
                          variant="caption" 
                          sx={{ 
                            opacity: 0.7,
                            bgcolor: isOwn ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.05)',
                            px: 0.75,
                            py: 0.25,
                            borderRadius: 0.5,
                          }}
                        >
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

            {/* Message Content with Markdown - skip for polls with poll data */}
            {(message.message_type !== 'file' && message.message_type !== 'poll' || message.is_deleted || (message.message_type === 'poll' && !poll)) && (
              <Box sx={{ '& > span': { wordBreak: 'break-word' } }}>
                <MarkdownRenderer 
                  content={message.content}
                  currentUserId={currentUserId}
                />
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
              <Typography
                variant="caption"
                sx={{ opacity: 0.7 }}
              >
                {formatTime(message.created_at)}
                {message.is_edited && ' (edited)'}
              </Typography>
              
              {/* Message Status for own messages: Sent → Delivered → Seen */}
              {isOwn && (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, ml: 1 }}>
                  {readBy.length > 0 ? (
                    // Message has been read by someone
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
                    // Message sent but not read yet - show single or double check
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
              <Tooltip title="Forward">
                <IconButton size="small" onClick={onForward}>
                  <ForwardIcon fontSize="small" />
                </IconButton>
              </Tooltip>
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
            <Tooltip
              key={emoji}
              title={info.users.join(', ')}
            >
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
